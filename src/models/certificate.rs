//! Certificate information types

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fmt;

/// Certificate revocation status
#[derive(Debug, Clone, Serialize)]
pub enum RevocationStatus {
    /// Certificate is not revoked
    Good,
    /// Certificate has been revoked
    Revoked {
        /// When the certificate was revoked
        revocation_date: Option<String>,
        /// Reason for revocation
        reason: Option<String>,
    },
    /// Revocation status could not be determined
    Unknown {
        /// Why the status is unknown
        reason: String,
    },
}

impl fmt::Display for RevocationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RevocationStatus::Good => write!(f, "Not Revoked"),
            RevocationStatus::Revoked { reason, .. } => {
                if let Some(r) = reason {
                    write!(f, "Revoked ({})", r)
                } else {
                    write!(f, "Revoked")
                }
            }
            RevocationStatus::Unknown { reason } => write!(f, "Unknown ({})", reason),
        }
    }
}

/// How the revocation status was determined
#[derive(Debug, Clone, Serialize)]
pub enum RevocationCheckMethod {
    /// OCSP response was stapled to the TLS handshake
    OcspStapled,
    /// OCSP response was fetched directly from the responder
    OcspDirect,
    /// Checked via CRL download
    Crl,
    /// No revocation check was performed
    None,
}

impl fmt::Display for RevocationCheckMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RevocationCheckMethod::OcspStapled => write!(f, "OCSP Stapling"),
            RevocationCheckMethod::OcspDirect => write!(f, "OCSP Direct"),
            RevocationCheckMethod::Crl => write!(f, "CRL"),
            RevocationCheckMethod::None => write!(f, "None"),
        }
    }
}

/// Revocation check result
#[derive(Debug, Clone, Serialize)]
pub struct RevocationInfo {
    /// The revocation status
    pub status: RevocationStatus,
    /// How the status was determined
    pub method: RevocationCheckMethod,
    /// OCSP responder URL or CRL URL that was checked
    pub source_url: Option<String>,
    /// Whether the response was stapled
    pub stapled: bool,
    /// Who issued the CRL or OCSP response
    pub response_issuer: Option<String>,
    /// When the CRL/OCSP response was produced
    pub this_update: Option<String>,
    /// When the next CRL/OCSP response is expected
    pub next_update: Option<String>,
    /// Total number of revoked certificates in the CRL (if CRL method)
    pub crl_entries: Option<usize>,
}

/// Detailed certificate information
#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    /// Certificate subject (CN)
    pub subject: String,
    /// Certificate issuer
    pub issuer: String,
    /// Serial number (hex string)
    pub serial: String,
    /// SHA-256 thumbprint
    pub thumbprint: String,
    /// Not valid before
    pub not_before: DateTime<Utc>,
    /// Not valid after
    pub not_after: DateTime<Utc>,
    /// Subject Alternative Names
    pub san: Vec<String>,
    /// Public key algorithm
    pub public_key_algorithm: String,
    /// Public key size in bits
    pub public_key_size: u32,
    /// Signature algorithm
    pub signature_algorithm: String,
    /// Whether this is a self-signed certificate
    pub is_self_signed: bool,
    /// Whether this is a CA certificate
    pub is_ca: bool,
    /// Certificate version
    pub version: u32,
    /// Key usage extensions
    pub key_usage: Vec<String>,
    /// Extended key usage
    pub extended_key_usage: Vec<String>,
    /// Raw certificate in DER format
    pub raw_der: Vec<u8>,
    /// OCSP responder URL from AIA extension
    pub ocsp_responder_url: Option<String>,
    /// CRL distribution points
    pub crl_distribution_points: Vec<String>,
    /// Revocation check result
    pub revocation: Option<RevocationInfo>,
}

impl CertificateInfo {
    /// Calculate days until expiry (negative if expired)
    pub fn days_until_expiry(&self) -> i64 {
        let now = Utc::now();
        let duration = self.not_after.signed_duration_since(now);
        duration.num_days()
    }

    /// Check if the certificate is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    /// Check if the certificate is not yet valid
    pub fn is_not_yet_valid(&self) -> bool {
        Utc::now() < self.not_before
    }

    /// Check if the certificate is currently valid (time-wise)
    pub fn is_time_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }

    /// Check if the certificate matches a given hostname
    pub fn matches_hostname(&self, hostname: &str) -> bool {
        // Check CN
        if self
            .subject
            .to_lowercase()
            .contains(&hostname.to_lowercase())
        {
            return true;
        }

        // Check SANs
        for san in &self.san {
            if san.to_lowercase() == hostname.to_lowercase() {
                return true;
            }

            // Handle wildcard matching
            if let Some(wildcard_domain) = san.strip_prefix("*.") {
                if let Some(host_domain) = hostname.split_once('.') {
                    if host_domain.1.to_lowercase() == wildcard_domain.to_lowercase() {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Get the PEM encoded certificate
    pub fn to_pem(&self) -> String {
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.raw_der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }
}

/// Summary of a certificate for display
#[derive(Debug, Clone, Serialize)]
pub struct CertificateSummary {
    /// Certificate type (Leaf, Intermediate, Root)
    pub cert_type: CertificateType,
    /// Subject common name
    pub subject_cn: String,
    /// Issuer common name
    pub issuer_cn: String,
    /// Valid from date
    pub valid_from: String,
    /// Valid until date
    pub valid_until: String,
    /// Days until expiry
    pub days_until_expiry: i64,
    /// Whether the certificate is valid
    pub is_valid: bool,
}

/// Type of certificate in the chain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CertificateType {
    Leaf,
    Intermediate,
    Root,
}

impl std::fmt::Display for CertificateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateType::Leaf => write!(f, "Server Certificate"),
            CertificateType::Intermediate => write!(f, "Intermediate CA"),
            CertificateType::Root => write!(f, "Root CA"),
        }
    }
}
