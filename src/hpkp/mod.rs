//! HTTP Public Key Pinning (HPKP) checking
//!
//! Note: HPKP has been deprecated by most browsers but this module
//! is included for legacy analysis and educational purposes.

use crate::certificate::CertificateInfo;
use crate::error::{Result, SslToolkitError};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// HPKP header information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkpInfo {
    pub present: bool,
    pub report_only: bool,
    pub max_age: Option<u64>,
    pub include_subdomains: bool,
    pub pins: Vec<HpkpPin>,
    pub report_uri: Option<String>,
    pub raw_header: Option<String>,
}

impl Default for HpkpInfo {
    fn default() -> Self {
        HpkpInfo {
            present: false,
            report_only: false,
            max_age: None,
            include_subdomains: false,
            pins: Vec::new(),
            report_uri: None,
            raw_header: None,
        }
    }
}

/// Individual HPKP pin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkpPin {
    pub algorithm: String,
    pub hash: String,
    pub matches_certificate: bool,
}

/// Check HPKP headers for a domain
pub async fn check_hpkp(domain: &str, port: u16) -> Result<HpkpInfo> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| SslToolkitError::Http(e))?;

    let url = format!("https://{}:{}", domain, port);

    let response = client
        .head(&url)
        .send()
        .await
        .map_err(|e| SslToolkitError::Http(e))?;

    let headers = response.headers();

    // Check for HPKP header (deprecated but still check for legacy)
    let hpkp_header = headers
        .get("public-key-pins")
        .or_else(|| headers.get("Public-Key-Pins"));

    let hpkp_report_header = headers
        .get("public-key-pins-report-only")
        .or_else(|| headers.get("Public-Key-Pins-Report-Only"));

    if let Some(header) = hpkp_header.or(hpkp_report_header) {
        let raw = header.to_str().unwrap_or("").to_string();
        let report_only = hpkp_report_header.is_some();
        parse_hpkp_header(&raw, report_only)
    } else {
        Ok(HpkpInfo::default())
    }
}

/// Parse HPKP header value
fn parse_hpkp_header(header: &str, report_only: bool) -> Result<HpkpInfo> {
    let mut info = HpkpInfo {
        present: true,
        report_only,
        raw_header: Some(header.to_string()),
        ..Default::default()
    };

    for directive in header.split(';') {
        let directive = directive.trim();

        if directive.starts_with("pin-sha256=") {
            let hash = directive
                .strip_prefix("pin-sha256=")
                .unwrap_or("")
                .trim_matches('"')
                .to_string();
            info.pins.push(HpkpPin {
                algorithm: "sha256".to_string(),
                hash,
                matches_certificate: false,
            });
        } else if directive.starts_with("max-age=") {
            if let Ok(age) = directive
                .strip_prefix("max-age=")
                .unwrap_or("0")
                .parse::<u64>()
            {
                info.max_age = Some(age);
            }
        } else if directive.eq_ignore_ascii_case("includeSubDomains") {
            info.include_subdomains = true;
        } else if directive.starts_with("report-uri=") {
            info.report_uri = Some(
                directive
                    .strip_prefix("report-uri=")
                    .unwrap_or("")
                    .trim_matches('"')
                    .to_string(),
            );
        }
    }

    Ok(info)
}

/// Generate SPKI pin for a certificate
pub fn generate_spki_pin(cert: &CertificateInfo) -> Result<String> {
    let cert_der = match &cert.raw_pem {
        Some(pem) => {
            pem::parse(pem)
                .map_err(|e| SslToolkitError::Certificate(format!("Failed to parse PEM: {}", e)))?
                .into_contents()
        }
        None => {
            return Err(SslToolkitError::Certificate(
                "No certificate data available".to_string(),
            ))
        }
    };

    // Extract SPKI and hash it
    let spki = extract_spki(&cert_der)?;
    let hash = Sha256::digest(&spki);
    let pin = STANDARD.encode(hash);

    Ok(pin)
}

fn extract_spki(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| SslToolkitError::Certificate(format!("Failed to parse certificate: {:?}", e)))?;

    Ok(cert.public_key().raw.to_vec())
}

/// Check if certificate matches any HPKP pin
pub fn certificate_matches_pins(cert: &CertificateInfo, pins: &[HpkpPin]) -> bool {
    if let Ok(cert_pin) = generate_spki_pin(cert) {
        pins.iter().any(|p| p.algorithm == "sha256" && p.hash == cert_pin)
    } else {
        false
    }
}

/// Generate HPKP header value for a certificate chain
pub fn generate_hpkp_header(
    certs: &[CertificateInfo],
    max_age: u64,
    include_subdomains: bool,
    report_uri: Option<&str>,
) -> Result<String> {
    let mut parts = Vec::new();

    for cert in certs {
        if let Ok(pin) = generate_spki_pin(cert) {
            parts.push(format!("pin-sha256=\"{}\"", pin));
        }
    }

    if parts.is_empty() {
        return Err(SslToolkitError::Certificate(
            "No valid pins could be generated".to_string(),
        ));
    }

    parts.push(format!("max-age={}", max_age));

    if include_subdomains {
        parts.push("includeSubDomains".to_string());
    }

    if let Some(uri) = report_uri {
        parts.push(format!("report-uri=\"{}\"", uri));
    }

    Ok(parts.join("; "))
}

/// Check HSTS header for a domain
pub async fn check_hsts(domain: &str, port: u16) -> Result<HstsInfo> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| SslToolkitError::Http(e))?;

    let url = format!("https://{}:{}", domain, port);

    let response = client
        .head(&url)
        .send()
        .await
        .map_err(|e| SslToolkitError::Http(e))?;

    let headers = response.headers();

    let hsts_header = headers
        .get("strict-transport-security")
        .or_else(|| headers.get("Strict-Transport-Security"));

    if let Some(header) = hsts_header {
        let raw = header.to_str().unwrap_or("").to_string();
        parse_hsts_header(&raw)
    } else {
        Ok(HstsInfo::default())
    }
}

/// HSTS header information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HstsInfo {
    pub present: bool,
    pub max_age: Option<u64>,
    pub include_subdomains: bool,
    pub preload: bool,
    pub raw_header: Option<String>,
}

fn parse_hsts_header(header: &str) -> Result<HstsInfo> {
    let mut info = HstsInfo {
        present: true,
        raw_header: Some(header.to_string()),
        ..Default::default()
    };

    for directive in header.split(';') {
        let directive = directive.trim();

        if directive.starts_with("max-age=") {
            if let Ok(age) = directive
                .strip_prefix("max-age=")
                .unwrap_or("0")
                .parse::<u64>()
            {
                info.max_age = Some(age);
            }
        } else if directive.eq_ignore_ascii_case("includeSubDomains") {
            info.include_subdomains = true;
        } else if directive.eq_ignore_ascii_case("preload") {
            info.preload = true;
        }
    }

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hpkp_header() {
        let header = r#"pin-sha256="abc123"; pin-sha256="def456"; max-age=5184000; includeSubDomains"#;
        let info = parse_hpkp_header(header, false).unwrap();

        assert!(info.present);
        assert!(!info.report_only);
        assert_eq!(info.max_age, Some(5184000));
        assert!(info.include_subdomains);
        assert_eq!(info.pins.len(), 2);
    }

    #[test]
    fn test_parse_hsts_header() {
        let header = "max-age=31536000; includeSubDomains; preload";
        let info = parse_hsts_header(header).unwrap();

        assert!(info.present);
        assert_eq!(info.max_age, Some(31536000));
        assert!(info.include_subdomains);
        assert!(info.preload);
    }
}
