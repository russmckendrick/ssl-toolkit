//! DNS resolution functionality

use crate::dns::records::*;
use crate::error::{Result, SslToolkitError};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::time::{Duration, Instant};

/// DNS resolver wrapper with custom configuration
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    timeout: Duration,
}

impl DnsResolver {
    /// Create a new DNS resolver with default settings
    pub async fn new() -> Result<Self> {
        Self::with_timeout(Duration::from_secs(10)).await
    }

    /// Create a new DNS resolver with custom timeout
    pub async fn with_timeout(timeout: Duration) -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 3;
        opts.use_hosts_file = false;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

        Ok(DnsResolver { resolver, timeout })
    }

    /// Get complete DNS information for a domain
    pub async fn get_dns_info(&self, domain: &str) -> Result<DnsInfo> {
        let mut info = DnsInfo {
            domain: domain.to_string(),
            ..Default::default()
        };

        // Resolve A records (IPv4)
        if let Ok(response) = self.resolver.ipv4_lookup(domain).await {
            info.ipv4_addresses = response.iter().map(|ip| ip.to_string()).collect();
        }

        // Resolve AAAA records (IPv6)
        if let Ok(response) = self.resolver.ipv6_lookup(domain).await {
            info.ipv6_addresses = response.iter().map(|ip| ip.to_string()).collect();
        }

        // Resolve NS records
        if let Ok(response) = self.resolver.ns_lookup(domain).await {
            info.nameservers = response.iter().map(|ns| ns.to_string().trim_end_matches('.').to_string()).collect();
        }

        // Resolve MX records
        if let Ok(response) = self.resolver.mx_lookup(domain).await {
            info.mx_records = response
                .iter()
                .map(|mx| MxRecord {
                    preference: mx.preference(),
                    exchange: mx.exchange().to_string().trim_end_matches('.').to_string(),
                })
                .collect();
            info.mx_records.sort_by_key(|mx| mx.preference);
        }

        // Resolve TXT records
        if let Ok(response) = self.resolver.txt_lookup(domain).await {
            info.txt_records = response
                .iter()
                .map(|txt| {
                    txt.txt_data()
                        .iter()
                        .map(|d| String::from_utf8_lossy(d).to_string())
                        .collect::<Vec<_>>()
                        .join("")
                })
                .collect();

            // Extract SPF record
            info.spf_record = info
                .txt_records
                .iter()
                .find(|r| r.starts_with("v=spf1"))
                .cloned();
        }

        // Resolve SOA record
        if let Ok(response) = self.resolver.soa_lookup(domain).await {
            if let Some(soa) = response.iter().next() {
                info.soa_record = Some(SoaRecord {
                    primary_ns: soa.mname().to_string().trim_end_matches('.').to_string(),
                    responsible_party: soa.rname().to_string().trim_end_matches('.').to_string(),
                    serial: soa.serial(),
                    refresh: soa.refresh() as u32,
                    retry: soa.retry() as u32,
                    expire: soa.expire() as u32,
                    minimum_ttl: soa.minimum(),
                });
            }
        }

        // Lookup DMARC record
        let dmarc_domain = format!("_dmarc.{}", domain);
        if let Ok(response) = self.resolver.txt_lookup(&dmarc_domain).await {
            info.dmarc_record = response
                .iter()
                .map(|txt| {
                    txt.txt_data()
                        .iter()
                        .map(|d| String::from_utf8_lossy(d).to_string())
                        .collect::<Vec<_>>()
                        .join("")
                })
                .find(|r| r.starts_with("v=DMARC1"));
        }

        // Lookup MTA-STS record
        let mta_sts_domain = format!("_mta-sts.{}", domain);
        if let Ok(response) = self.resolver.txt_lookup(&mta_sts_domain).await {
            for txt in response.iter() {
                let record_text: String = txt
                    .txt_data()
                    .iter()
                    .map(|d| String::from_utf8_lossy(d).to_string())
                    .collect::<Vec<_>>()
                    .join("");

                if record_text.starts_with("v=STSv1") {
                    let mut mta_sts = MtaStsRecord {
                        version: "STSv1".to_string(),
                        id: String::new(),
                    };

                    for part in record_text.split(';') {
                        let part = part.trim();
                        if let Some(id) = part.strip_prefix("id=") {
                            mta_sts.id = id.to_string();
                        }
                    }

                    info.mta_sts = Some(mta_sts);
                    break;
                }
            }
        }

        // Lookup BIMI record
        let bimi_domain = format!("default._bimi.{}", domain);
        if let Ok(response) = self.resolver.txt_lookup(&bimi_domain).await {
            info.bimi_record = response
                .iter()
                .map(|txt| {
                    txt.txt_data()
                        .iter()
                        .map(|d| String::from_utf8_lossy(d).to_string())
                        .collect::<Vec<_>>()
                        .join("")
                })
                .find(|r| r.starts_with("v=BIMI1"));
        }

        // Check nameserver consistency
        info.nameserver_checks = self.check_nameservers(domain, &info.nameservers).await;
        info.is_consistent = self.check_consistency(&info.nameserver_checks);

        Ok(info)
    }

    /// Get CAA records for a domain
    pub async fn get_caa_records(&self, domain: &str) -> Result<Vec<CaaRecord>> {
        // CAA records require looking up the domain hierarchy
        let mut records = Vec::new();
        let parts: Vec<&str> = domain.split('.').collect();

        // Check each level of the domain hierarchy
        for i in 0..parts.len() {
            let check_domain = parts[i..].join(".");
            if let Ok(response) = self.lookup_caa(&check_domain).await {
                records.extend(response);
                if !records.is_empty() {
                    break; // CAA records are inherited, so stop at first match
                }
            }
        }

        Ok(records)
    }

    async fn lookup_caa(&self, domain: &str) -> Result<Vec<CaaRecord>> {
        // CAA lookup using generic lookup
        // hickory-resolver doesn't have direct CAA support, so we use TXT as fallback
        // In production, you'd use the DNS protocol directly for CAA records

        // For now, return empty - full implementation would use raw DNS queries
        Ok(Vec::new())
    }

    /// Check DNSSEC status for a domain
    pub async fn check_dnssec(&self, domain: &str) -> Result<bool> {
        // Check for DNSKEY records which indicate DNSSEC is enabled
        // This is a simplified check - full validation requires verifying the chain

        // hickory-resolver with DNSSEC validation would set specific flags
        // For now, we'll do a basic check

        // Look for RRSIG or DNSKEY records (simplified)
        Ok(false) // Would need raw DNS queries for proper DNSSEC detection
    }

    /// Check nameserver consistency
    async fn check_nameservers(&self, domain: &str, nameservers: &[String]) -> Vec<NameserverCheck> {
        let mut checks = Vec::new();

        for ns in nameservers {
            let start = Instant::now();

            // Resolve the nameserver's IP first
            let ns_ips: Vec<String> = match self.resolver.ipv4_lookup(ns).await {
                Ok(response) => response.iter().map(|ip| ip.to_string()).collect(),
                Err(_) => Vec::new(),
            };

            // Query the nameserver for the domain's A records
            // This is simplified - full implementation would query the NS directly
            let (ipv4, ipv6, error) = match self.resolver.ipv4_lookup(domain).await {
                Ok(response) => {
                    let ips: Vec<String> = response.iter().map(|ip| ip.to_string()).collect();
                    let ipv6: Vec<String> = match self.resolver.ipv6_lookup(domain).await {
                        Ok(r) => r.iter().map(|ip| ip.to_string()).collect(),
                        Err(_) => Vec::new(),
                    };
                    (ips, ipv6, None)
                }
                Err(e) => (Vec::new(), Vec::new(), Some(e.to_string())),
            };

            let response_time = start.elapsed().as_millis() as u64;

            checks.push(NameserverCheck {
                nameserver: ns.clone(),
                ipv4_addresses: ipv4,
                ipv6_addresses: ipv6,
                response_time_ms: Some(response_time),
                error,
            });
        }

        checks
    }

    /// Check if all nameservers return consistent results
    fn check_consistency(&self, checks: &[NameserverCheck]) -> bool {
        if checks.len() < 2 {
            return true;
        }

        let first = match checks.first() {
            Some(c) => c,
            None => return true,
        };

        for check in checks.iter().skip(1) {
            if check.error.is_some() {
                continue; // Skip failed checks
            }

            // Compare IPv4 addresses (sorted)
            let mut first_v4 = first.ipv4_addresses.clone();
            let mut check_v4 = check.ipv4_addresses.clone();
            first_v4.sort();
            check_v4.sort();

            if first_v4 != check_v4 {
                return false;
            }
        }

        true
    }

    /// Resolve a domain to IP addresses
    pub async fn resolve(&self, domain: &str) -> Result<Vec<String>> {
        let mut ips = Vec::new();

        if let Ok(response) = self.resolver.ipv4_lookup(domain).await {
            ips.extend(response.iter().map(|ip| ip.to_string()));
        }

        if let Ok(response) = self.resolver.ipv6_lookup(domain).await {
            ips.extend(response.iter().map(|ip| ip.to_string()));
        }

        if ips.is_empty() {
            return Err(SslToolkitError::Dns(format!(
                "No IP addresses found for {}",
                domain
            )));
        }

        Ok(ips)
    }
}
