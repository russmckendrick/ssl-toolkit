//! DNS resolution result types

use serde::{Serialize, Serializer};
use std::net::IpAddr;
use std::time::Duration;

fn serialize_duration_ms<S: Serializer>(duration: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f64(duration.as_secs_f64() * 1000.0)
}

/// Result from a DNS resolution query
#[derive(Debug, Clone, Serialize)]
pub struct DnsResult {
    /// Name of the DNS provider used
    pub provider: String,
    /// Resolved IP addresses
    pub addresses: Vec<IpAddr>,
    /// Time taken for the query (milliseconds)
    #[serde(serialize_with = "serialize_duration_ms")]
    pub query_time: Duration,
    /// Error message if resolution failed
    pub error: Option<String>,
}

impl DnsResult {
    /// Create a successful DNS result
    pub fn success(provider: String, addresses: Vec<IpAddr>, query_time: Duration) -> Self {
        Self {
            provider,
            addresses,
            query_time,
            error: None,
        }
    }

    /// Create a failed DNS result
    pub fn failure(provider: String, error: String, query_time: Duration) -> Self {
        Self {
            provider,
            addresses: vec![],
            query_time,
            error: Some(error),
        }
    }

    /// Check if the resolution was successful
    pub fn is_success(&self) -> bool {
        !self.addresses.is_empty() && self.error.is_none()
    }

    /// Get the first resolved address, if any
    pub fn first_address(&self) -> Option<IpAddr> {
        self.addresses.first().copied()
    }
}
