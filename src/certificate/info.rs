//! Certificate information structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Distinguished Name components
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DistinguishedName {
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
}

impl fmt::Display for DistinguishedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(cn) = &self.common_name {
            parts.push(format!("CN={}", cn));
        }
        if let Some(o) = &self.organization {
            parts.push(format!("O={}", o));
        }
        if let Some(ou) = &self.organizational_unit {
            parts.push(format!("OU={}", ou));
        }
        if let Some(c) = &self.country {
            parts.push(format!("C={}", c));
        }
        if let Some(st) = &self.state {
            parts.push(format!("ST={}", st));
        }
        if let Some(l) = &self.locality {
            parts.push(format!("L={}", l));
        }
        write!(f, "{}", parts.join(", "))
    }
}

/// Trust status of a certificate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustStatus {
    Trusted,
    Untrusted,
    SelfSigned,
    Expired,
    NotYetValid,
    Revoked,
    Unknown,
}

impl fmt::Display for TrustStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustStatus::Trusted => write!(f, "Trusted"),
            TrustStatus::Untrusted => write!(f, "Untrusted"),
            TrustStatus::SelfSigned => write!(f, "Self-Signed"),
            TrustStatus::Expired => write!(f, "Expired"),
            TrustStatus::NotYetValid => write!(f, "Not Yet Valid"),
            TrustStatus::Revoked => write!(f, "Revoked"),
            TrustStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

/// OCSP status of a certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OcspStatus {
    Good,
    Revoked {
        revocation_time: Option<DateTime<Utc>>,
        reason: Option<String>,
    },
    Unknown,
    Error(String),
}

impl fmt::Display for OcspStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OcspStatus::Good => write!(f, "Good"),
            OcspStatus::Revoked {
                revocation_time,
                reason,
            } => {
                let mut s = "Revoked".to_string();
                if let Some(time) = revocation_time {
                    s.push_str(&format!(" at {}", time.format("%Y-%m-%d %H:%M:%S UTC")));
                }
                if let Some(r) = reason {
                    s.push_str(&format!(" ({})", r));
                }
                write!(f, "{}", s)
            }
            OcspStatus::Unknown => write!(f, "Unknown"),
            OcspStatus::Error(e) => write!(f, "Error: {}", e),
        }
    }
}

/// Key algorithm type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    Rsa(u32),       // bit size
    Ecdsa(String),  // curve name
    Ed25519,
    Ed448,
    Dsa(u32),
    Unknown(String),
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyAlgorithm::Rsa(bits) => write!(f, "RSA {} bits", bits),
            KeyAlgorithm::Ecdsa(curve) => write!(f, "ECDSA ({})", curve),
            KeyAlgorithm::Ed25519 => write!(f, "Ed25519"),
            KeyAlgorithm::Ed448 => write!(f, "Ed448"),
            KeyAlgorithm::Dsa(bits) => write!(f, "DSA {} bits", bits),
            KeyAlgorithm::Unknown(s) => write!(f, "Unknown ({})", s),
        }
    }
}

/// Complete certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub version: u32,
    pub serial_number: String,
    pub subject: DistinguishedName,
    pub issuer: DistinguishedName,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub days_until_expiry: i64,
    pub signature_algorithm: String,
    pub key_algorithm: KeyAlgorithm,
    pub key_size: u32,
    pub subject_alt_names: Vec<String>,
    pub is_validated: bool,
    pub validation_error: Option<String>,
    pub trust_status: TrustStatus,
    pub ocsp_status: Option<OcspStatus>,
    pub ocsp_stapling: bool,
    pub ct_logged: bool,
    pub is_ca: bool,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
    pub authority_info_access: Option<AuthorityInfoAccess>,
    pub crl_distribution_points: Vec<String>,
    pub certificate_policies: Vec<String>,
    pub raw_pem: Option<String>,
}

impl CertificateInfo {
    /// Check if the certificate is currently valid (not expired and not yet valid)
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }

    /// Check if the certificate is expiring soon (within given days)
    pub fn is_expiring_soon(&self, days: i64) -> bool {
        self.days_until_expiry >= 0 && self.days_until_expiry <= days
    }

    /// Get validity period in days
    pub fn validity_period_days(&self) -> i64 {
        (self.not_after - self.not_before).num_days()
    }
}

/// Authority Information Access extension data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityInfoAccess {
    pub ocsp_responders: Vec<String>,
    pub ca_issuers: Vec<String>,
}

/// Certificate chain information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChain {
    pub certificates: Vec<CertificateInfo>,
    pub is_complete: bool,
    pub chain_length: usize,
    pub root_in_store: bool,
}

impl CertificateChain {
    pub fn new() -> Self {
        CertificateChain {
            certificates: Vec::new(),
            is_complete: false,
            chain_length: 0,
            root_in_store: false,
        }
    }

    /// Get the leaf (end-entity) certificate
    pub fn leaf(&self) -> Option<&CertificateInfo> {
        self.certificates.first()
    }

    /// Get intermediate certificates
    pub fn intermediates(&self) -> &[CertificateInfo] {
        if self.certificates.len() > 1 {
            &self.certificates[1..self.certificates.len().saturating_sub(1)]
        } else {
            &[]
        }
    }

    /// Get the root certificate if present
    pub fn root(&self) -> Option<&CertificateInfo> {
        if self.certificates.len() > 1 {
            self.certificates.last()
        } else {
            None
        }
    }
}

impl Default for CertificateChain {
    fn default() -> Self {
        Self::new()
    }
}

/// SSL check result containing all information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCheckResult {
    pub domain: String,
    pub ip_address: Option<String>,
    pub port: u16,
    pub chain: CertificateChain,
    pub protocol_version: String,
    pub cipher_suite: Option<String>,
    pub check_time: DateTime<Utc>,
    pub response_time_ms: u64,
}
