//! WHOIS lookup functionality
//!
//! Performs WHOIS queries for domain registration information using
//! the `whois-rust` crate with the node-whois servers.json database.

use crate::utils::WhoisError;
use std::time::Duration;
use whois_rust::{WhoIs, WhoIsLookupOptions};

/// Embedded node-whois servers.json for comprehensive TLD coverage
const SERVERS_JSON: &str = include_str!("servers.json");

/// WHOIS lookup result
#[derive(Debug, Clone)]
pub struct WhoisInfo {
    /// Domain registrar
    pub registrar: Option<String>,
    /// Creation date
    pub created: Option<String>,
    /// Expiration date
    pub expires: Option<String>,
    /// Last updated
    pub updated: Option<String>,
    /// Nameservers
    pub nameservers: Vec<String>,
    /// Domain status
    pub status: Vec<String>,
    /// Raw WHOIS response
    pub raw: String,
}

/// WHOIS checker
pub struct WhoisChecker {
    timeout: Duration,
    retry_count: u32,
    backoff_base: Duration,
}

impl WhoisChecker {
    /// Create a new WHOIS checker
    pub fn new(timeout: Duration, retry_count: u32, backoff_base: Duration) -> Self {
        Self {
            timeout,
            retry_count,
            backoff_base,
        }
    }

    /// Perform a WHOIS lookup for the given domain.
    /// Automatically extracts the registered domain (strips subdomains like www.).
    pub async fn lookup(&self, domain: &str) -> Result<WhoisInfo, WhoisError> {
        let domain = extract_registered_domain(domain);
        let mut last_error = None;

        for attempt in 0..self.retry_count {
            if attempt > 0 {
                // Exponential backoff
                let delay = self.backoff_base * 2u32.pow(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            match self.do_lookup(&domain).await {
                Ok(info) => return Ok(info),
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| WhoisError::LookupFailed {
            domain,
            message: "Unknown error".to_string(),
        }))
    }

    async fn do_lookup(&self, domain: &str) -> Result<WhoisInfo, WhoisError> {
        let domain_owned = domain.to_string();
        let timeout = self.timeout;

        let raw = tokio::time::timeout(timeout, async {
            let domain_clone = domain_owned.clone();
            let timeout_ms = timeout.as_millis() as u64;
            tokio::task::spawn_blocking(move || {
                let whois = WhoIs::from_string(SERVERS_JSON).map_err(|e| {
                    WhoisError::LookupFailed {
                        domain: domain_clone.clone(),
                        message: format!("Failed to load WHOIS servers: {}", e),
                    }
                })?;

                let mut options =
                    WhoIsLookupOptions::from_string(&domain_clone).map_err(|e| {
                        WhoisError::LookupFailed {
                            domain: domain_clone.clone(),
                            message: format!("Invalid domain: {}", e),
                        }
                    })?;
                options.timeout = Some(Duration::from_millis(timeout_ms));

                whois.lookup(options).map_err(|e| WhoisError::LookupFailed {
                    domain: domain_clone,
                    message: e.to_string(),
                })
            })
            .await
            .map_err(|e| WhoisError::LookupFailed {
                domain: domain_owned.clone(),
                message: format!("Task join error: {}", e),
            })?
        })
        .await
        .map_err(|_| WhoisError::Timeout {
            domain: domain.to_string(),
        })??;

        let info = build_whois_info(&raw);
        Ok(info)
    }
}

/// Build WhoisInfo by parsing the raw WHOIS response
fn build_whois_info(raw: &str) -> WhoisInfo {
    let mut info = WhoisInfo {
        registrar: None,
        created: None,
        expires: None,
        updated: None,
        nameservers: Vec::new(),
        status: Vec::new(),
        raw: raw.to_string(),
    };

    // Track whether we're inside a "Registrar:" block (Nominet .uk style)
    let mut in_registrar_block = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();

        // Detect Nominet-style indented registrar block:
        //   Registrar:
        //       Name:    Some Registrar Ltd
        if in_registrar_block {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Indented line inside registrar block
                if info.registrar.is_none() && lower.trim_start().starts_with("name:") {
                    info.registrar = extract_full_value(trimmed).filter(|s| !s.is_empty());
                }
                // Stay in registrar block for subsequent indented lines
                continue;
            } else {
                // Non-indented line ends the block
                in_registrar_block = false;
            }
        }

        // Registrar (single-line formats)
        if info.registrar.is_none()
            && (lower.starts_with("registrar:")
                || lower.starts_with("registrar name:")
                || lower.starts_with("sponsoring registrar:"))
        {
            let val = extract_full_value(trimmed).filter(|s| !s.is_empty());
            if val.is_some() {
                info.registrar = val;
            } else if lower == "registrar:" {
                // Empty value after "Registrar:" — enter indented block mode
                in_registrar_block = true;
            }
        }

        // Creation date
        if info.created.is_none()
            && (lower.starts_with("creation date:")
                || lower.starts_with("created:")
                || lower.starts_with("created on:")
                || lower.starts_with("registration date:")
                || lower.starts_with("registered on:"))
        {
            info.created = extract_full_value(trimmed).filter(|s| !s.is_empty());
        }

        // Expiration date
        if info.expires.is_none()
            && (lower.starts_with("registry expiry date:")
                || lower.starts_with("registrar registration expiration date:")
                || lower.starts_with("expiration date:")
                || lower.starts_with("expires:")
                || lower.starts_with("expires on:")
                || lower.starts_with("expiry date:"))
        {
            info.expires = extract_full_value(trimmed).filter(|s| !s.is_empty());
        }

        // Updated date
        if info.updated.is_none()
            && (lower.starts_with("updated date:")
                || lower.starts_with("last updated:")
                || lower.starts_with("last modified:"))
        {
            info.updated = extract_full_value(trimmed).filter(|s| !s.is_empty());
        }

        // Nameservers
        if lower.starts_with("name server:") || lower.starts_with("nserver:") {
            if let Some(ns) = extract_value(trimmed) {
                let ns = ns.to_lowercase();
                if !ns.is_empty() && !info.nameservers.contains(&ns) {
                    info.nameservers.push(ns);
                }
            }
        }

        // Domain status
        if lower.starts_with("domain status:") || lower.starts_with("status:") {
            if let Some(status) = extract_value(trimmed) {
                if !status.is_empty() && !info.status.contains(&status) {
                    info.status.push(status);
                }
            }
        }
    }

    info
}

/// Extract the registered domain from a full domain name.
/// e.g. "www.russ.fm" → "russ.fm", "sub.example.co.uk" → "example.co.uk"
fn extract_registered_domain(domain: &str) -> String {
    let domain = domain.trim().trim_end_matches('.');

    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() <= 2 {
        return domain.to_string();
    }

    // Known two-part TLDs (public suffix approximation)
    let two_part_tlds = [
        "co.uk", "org.uk", "me.uk", "net.uk", "ac.uk",
        "co.jp", "or.jp", "ne.jp", "ac.jp",
        "com.au", "net.au", "org.au", "edu.au",
        "co.nz", "net.nz", "org.nz",
        "co.za", "org.za", "web.za",
        "com.br", "net.br", "org.br",
        "com.mx", "org.mx", "net.mx",
        "com.cn", "net.cn", "org.cn",
        "co.in", "net.in", "org.in",
        "co.kr", "or.kr", "ne.kr",
        "com.tw", "org.tw", "net.tw",
        "com.sg", "net.sg", "org.sg",
        "com.hk", "net.hk", "org.hk",
        "co.il", "org.il", "net.il",
        "com.ar", "net.ar", "org.ar",
        "com.tr", "net.tr", "org.tr",
        "co.th", "or.th", "in.th",
        "com.my", "net.my", "org.my",
        "co.id", "or.id", "web.id",
        "com.ph", "net.ph", "org.ph",
        "com.vn", "net.vn", "org.vn",
        "co.ke", "or.ke",
        "com.ng", "net.ng", "org.ng",
        "co.tz", "or.tz",
        "com.ua", "net.ua", "org.ua",
        "com.pl", "net.pl", "org.pl",
        "co.hu", "org.hu",
        "com.ro", "org.ro",
        "co.at", "or.at",
        "com.de", "org.de",
        "com.es", "org.es", "nom.es",
        "com.pt", "org.pt",
        "co.it",
        "asso.fr", "nom.fr",
        "gov.uk", "gov.au", "gov.in", "gov.br",
        "edu.au", "edu.cn",
    ];

    let lower = domain.to_lowercase();
    for tld in &two_part_tlds {
        if lower.ends_with(tld) {
            // registered domain = label + two-part TLD → need 3 parts from the end
            if parts.len() >= 3 {
                return parts[parts.len() - 3..].join(".");
            }
            return domain.to_string();
        }
    }

    // Default: registered domain is last two labels
    parts[parts.len() - 2..].join(".")
}

/// Extract value after the first colon (first segment only)
fn extract_value(line: &str) -> Option<String> {
    line.split(':').nth(1).map(|v| v.trim().to_string())
}

/// Extract full value after the first colon (preserving colons in timestamps)
fn extract_full_value(line: &str) -> Option<String> {
    let pos = line.find(':')?;
    Some(line[pos + 1..].trim().to_string())
}

impl Default for WhoisChecker {
    fn default() -> Self {
        Self::new(
            Duration::from_secs(10),
            3,
            Duration::from_millis(1000),
        )
    }
}
