//! Certificate Transparency log integration
//!
//! This module provides functionality for querying Certificate Transparency logs
//! to find certificates issued for a domain.

use crate::error::{Result, SslToolkitError};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Certificate entry from CT logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtLogEntry {
    pub issuer_name: String,
    pub common_name: String,
    pub name_value: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub serial_number: String,
    pub entry_timestamp: DateTime<Utc>,
    pub log_name: Option<String>,
}

/// CT log search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtSearchResult {
    pub domain: String,
    pub total_entries: usize,
    pub entries: Vec<CtLogEntry>,
    pub search_time_ms: u64,
}

/// Response from crt.sh API
#[derive(Debug, Deserialize)]
struct CrtShEntry {
    issuer_name: Option<String>,
    common_name: Option<String>,
    name_value: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    serial_number: Option<String>,
    entry_timestamp: Option<String>,
}

/// Search CT logs for certificates issued for a domain
pub async fn search_ct_logs(domain: &str, include_expired: bool) -> Result<CtSearchResult> {
    let start = std::time::Instant::now();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| SslToolkitError::Http(e))?;

    // Using crt.sh API (free CT log aggregator)
    let url = if include_expired {
        format!("https://crt.sh/?q=%25.{}&output=json", domain)
    } else {
        format!(
            "https://crt.sh/?q=%25.{}&output=json&exclude=expired",
            domain
        )
    };

    let response = client
        .get(&url)
        .header("User-Agent", "ssl-toolkit/0.1.0")
        .send()
        .await
        .map_err(|e| SslToolkitError::Http(e))?;

    if !response.status().is_success() {
        return Err(SslToolkitError::CertificateTransparency(format!(
            "CT log query failed with status: {}",
            response.status()
        )));
    }

    let text = response
        .text()
        .await
        .map_err(|e| SslToolkitError::Http(e))?;

    // Handle empty response
    if text.trim().is_empty() || text.trim() == "[]" {
        return Ok(CtSearchResult {
            domain: domain.to_string(),
            total_entries: 0,
            entries: Vec::new(),
            search_time_ms: start.elapsed().as_millis() as u64,
        });
    }

    let crt_entries: Vec<CrtShEntry> = serde_json::from_str(&text)
        .map_err(|e| SslToolkitError::Parse(format!("Failed to parse CT log response: {}", e)))?;

    let mut entries: Vec<CtLogEntry> = crt_entries
        .into_iter()
        .filter_map(|e| convert_crt_entry(e).ok())
        .collect();

    // Sort by entry timestamp (newest first)
    entries.sort_by(|a, b| b.entry_timestamp.cmp(&a.entry_timestamp));

    // Remove duplicates based on serial number
    entries.dedup_by(|a, b| a.serial_number == b.serial_number);

    let search_time = start.elapsed().as_millis() as u64;

    Ok(CtSearchResult {
        domain: domain.to_string(),
        total_entries: entries.len(),
        entries,
        search_time_ms: search_time,
    })
}

fn convert_crt_entry(entry: CrtShEntry) -> Result<CtLogEntry> {
    let parse_datetime = |s: &str| -> Result<DateTime<Utc>> {
        // Try different date formats
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
            return Ok(Utc.from_utc_datetime(&dt));
        }
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
            return Ok(Utc.from_utc_datetime(&dt));
        }
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
            return Ok(Utc.from_utc_datetime(&dt));
        }
        Err(SslToolkitError::Parse(format!(
            "Failed to parse date: {}",
            s
        )))
    };

    Ok(CtLogEntry {
        issuer_name: entry.issuer_name.unwrap_or_default(),
        common_name: entry.common_name.unwrap_or_default(),
        name_value: entry.name_value.unwrap_or_default(),
        not_before: entry
            .not_before
            .as_deref()
            .map(parse_datetime)
            .transpose()?
            .unwrap_or_else(Utc::now),
        not_after: entry
            .not_after
            .as_deref()
            .map(parse_datetime)
            .transpose()?
            .unwrap_or_else(Utc::now),
        serial_number: entry.serial_number.unwrap_or_default(),
        entry_timestamp: entry
            .entry_timestamp
            .as_deref()
            .map(parse_datetime)
            .transpose()?
            .unwrap_or_else(Utc::now),
        log_name: Some("crt.sh".to_string()),
    })
}

/// Check if a certificate is logged in CT
pub async fn is_certificate_in_ct(serial: &str, domain: &str) -> Result<bool> {
    let result = search_ct_logs(domain, true).await?;

    let serial_clean = serial.replace(":", "").to_lowercase();

    Ok(result
        .entries
        .iter()
        .any(|e| e.serial_number.to_lowercase() == serial_clean))
}

/// Get recent certificates issued for a domain
pub async fn get_recent_certificates(domain: &str, limit: usize) -> Result<Vec<CtLogEntry>> {
    let mut result = search_ct_logs(domain, false).await?;
    result.entries.truncate(limit);
    Ok(result.entries)
}

/// Check for potentially suspicious certificates (e.g., from unexpected issuers)
pub fn detect_suspicious_certificates<'a>(
    entries: &'a [CtLogEntry],
    expected_issuers: &[&str],
) -> Vec<&'a CtLogEntry> {
    entries
        .iter()
        .filter(|e| {
            !expected_issuers
                .iter()
                .any(|issuer| e.issuer_name.contains(issuer))
        })
        .collect()
}

/// Get certificate issuance timeline
pub fn get_issuance_timeline(entries: &[CtLogEntry]) -> Vec<(DateTime<Utc>, usize)> {
    use std::collections::HashMap;

    let mut by_month: HashMap<String, usize> = HashMap::new();

    for entry in entries {
        let key = entry.entry_timestamp.format("%Y-%m").to_string();
        *by_month.entry(key).or_insert(0) += 1;
    }

    let mut timeline: Vec<(DateTime<Utc>, usize)> = by_month
        .into_iter()
        .filter_map(|(k, v)| {
            chrono::NaiveDate::parse_from_str(&format!("{}-01", k), "%Y-%m-%d")
                .ok()
                .map(|d| (Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0).unwrap()), v))
        })
        .collect();

    timeline.sort_by_key(|(dt, _)| *dt);
    timeline
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_suspicious_certificates() {
        let entries = vec![
            CtLogEntry {
                issuer_name: "Let's Encrypt Authority X3".to_string(),
                common_name: "example.com".to_string(),
                name_value: "example.com".to_string(),
                not_before: Utc::now(),
                not_after: Utc::now(),
                serial_number: "abc123".to_string(),
                entry_timestamp: Utc::now(),
                log_name: None,
            },
            CtLogEntry {
                issuer_name: "Unknown CA".to_string(),
                common_name: "example.com".to_string(),
                name_value: "example.com".to_string(),
                not_before: Utc::now(),
                not_after: Utc::now(),
                serial_number: "def456".to_string(),
                entry_timestamp: Utc::now(),
                log_name: None,
            },
        ];

        let expected_issuers = &["Let's Encrypt", "DigiCert"];
        let suspicious = detect_suspicious_certificates(&entries, expected_issuers);

        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].issuer_name, "Unknown CA");
    }
}
