//! DNS resolution checker
//!
//! Performs DNS lookups using multiple providers for comparison.

use crate::config::settings::DnsProvider;
use crate::models::DnsResult;
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Type alias for the Tokio async resolver
type TokioResolver = Resolver<TokioConnectionProvider>;

/// DNS checker that resolves domains using multiple providers
pub struct DnsChecker {
    providers: Vec<DnsProvider>,
    timeout: Duration,
}

impl DnsChecker {
    /// Create a new DNS checker with the given providers
    pub fn new(providers: Vec<DnsProvider>) -> Self {
        Self {
            providers,
            timeout: Duration::from_secs(5),
        }
    }

    /// Set the query timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Resolve a domain using all configured providers
    pub async fn resolve_all(&self, domain: &str) -> Vec<DnsResult> {
        let mut results = Vec::new();

        for provider in &self.providers {
            let result = self.resolve_with_provider(domain, provider).await;
            results.push(result);
        }

        results
    }

    /// Resolve a domain using a specific provider
    async fn resolve_with_provider(&self, domain: &str, provider: &DnsProvider) -> DnsResult {
        let start = Instant::now();

        let resolver: TokioResolver = if provider.servers.is_empty() {
            // Use system resolver
            match TokioResolver::builder_tokio() {
                Ok(builder) => builder.build(),
                Err(e) => {
                    return DnsResult::failure(
                        provider.name.clone(),
                        format!("Failed to create system resolver: {}", e),
                        start.elapsed(),
                    );
                }
            }
        } else {
            // Use custom nameservers
            let mut config = ResolverConfig::new();
            for server in &provider.servers {
                let socket_addr = SocketAddr::new(*server, 53);
                config.add_name_server(NameServerConfig::new(socket_addr, Protocol::Udp));
            }

            TokioResolver::builder_with_config(config, TokioConnectionProvider::default()).build()
        };

        // Perform the lookup
        match tokio::time::timeout(self.timeout, resolver.lookup_ip(domain)).await {
            Ok(Ok(lookup)) => {
                let addresses: Vec<IpAddr> = lookup.iter().collect();
                DnsResult::success(provider.name.clone(), addresses, start.elapsed())
            }
            Ok(Err(e)) => DnsResult::failure(provider.name.clone(), e.to_string(), start.elapsed()),
            Err(_) => DnsResult::failure(
                provider.name.clone(),
                "DNS query timed out".to_string(),
                start.elapsed(),
            ),
        }
    }

    /// Resolve using only the system resolver
    pub async fn resolve_system(&self, domain: &str) -> DnsResult {
        let system_provider = DnsProvider {
            name: "System".to_string(),
            servers: vec![],
            description: "System resolver".to_string(),
        };
        self.resolve_with_provider(domain, &system_provider).await
    }

    /// Get the first successful IP address from any provider
    pub async fn resolve_first(&self, domain: &str) -> Option<IpAddr> {
        for provider in &self.providers {
            let result = self.resolve_with_provider(domain, provider).await;
            if let Some(ip) = result.first_address() {
                return Some(ip);
            }
        }
        None
    }
}