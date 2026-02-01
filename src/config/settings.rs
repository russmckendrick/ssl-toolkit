//! Application settings configuration
//!
//! Defines DNS providers, SSL settings, and other runtime configuration.

use crate::utils::ConfigError;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

/// DNS provider configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DnsProvider {
    pub name: String,
    pub servers: Vec<IpAddr>,
    pub description: String,
}

/// SSL/TLS settings
#[derive(Debug, Clone, Deserialize)]
pub struct SslSettings {
    pub connect_timeout_secs: u64,
    pub handshake_timeout_secs: u64,
    pub check_legacy_protocols: bool,
    pub check_weak_ciphers: bool,
    #[serde(default = "default_ocsp_timeout")]
    pub ocsp_timeout_secs: u64,
    #[serde(default = "default_check_revocation")]
    pub check_revocation: bool,
}

fn default_ocsp_timeout() -> u64 {
    5
}

fn default_check_revocation() -> bool {
    true
}

impl Default for SslSettings {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 10,
            handshake_timeout_secs: 10,
            check_legacy_protocols: true,
            check_weak_ciphers: true,
            ocsp_timeout_secs: 5,
            check_revocation: true,
        }
    }
}

impl SslSettings {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }

    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout_secs)
    }

    pub fn ocsp_timeout(&self) -> Duration {
        Duration::from_secs(self.ocsp_timeout_secs)
    }
}

/// WHOIS settings
#[derive(Debug, Clone, Deserialize)]
pub struct WhoisSettings {
    pub timeout_secs: u64,
    pub retry_count: u32,
    pub backoff_base_ms: u64,
}

impl Default for WhoisSettings {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            retry_count: 3,
            backoff_base_ms: 1000,
        }
    }
}

/// Application settings
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub dns_providers: Vec<DnsProvider>,
    #[serde(default)]
    pub ssl: SslSettings,
    #[serde(default)]
    pub whois: WhoisSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            dns_providers: vec![
                DnsProvider {
                    name: "System".to_string(),
                    servers: vec![],
                    description: "System default DNS resolver".to_string(),
                },
                DnsProvider {
                    name: "Google".to_string(),
                    servers: vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()],
                    description: "Google Public DNS".to_string(),
                },
                DnsProvider {
                    name: "Cloudflare".to_string(),
                    servers: vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()],
                    description: "Cloudflare DNS".to_string(),
                },
                DnsProvider {
                    name: "OpenDNS".to_string(),
                    servers: vec![
                        "208.67.222.222".parse().unwrap(),
                        "208.67.220.220".parse().unwrap(),
                    ],
                    description: "Cisco OpenDNS".to_string(),
                },
            ],
            ssl: SslSettings::default(),
            whois: WhoisSettings::default(),
        }
    }
}

impl Settings {
    /// Load settings from the default config file
    pub fn load_default() -> Result<Self, ConfigError> {
        let config_path = Path::new("config/default.toml");
        if config_path.exists() {
            Self::load_from_file(config_path)
        } else {
            Ok(Self::default())
        }
    }

    /// Load settings from a specific file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|_| ConfigError::FileNotFound {
            path: path.display().to_string(),
        })?;

        toml::from_str(&content).map_err(|e| ConfigError::ParseError {
            message: e.to_string(),
        })
    }
}
