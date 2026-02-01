//! Certificate comparison types
//!
//! Used to compare certificates returned from different IP addresses.

use serde::Serialize;
use std::net::IpAddr;

/// Certificate comparison result for a single IP
#[derive(Debug, Clone, Serialize)]
pub struct CertComparisonEntry {
    /// IP address that was checked
    pub ip: IpAddr,
    /// Certificate thumbprint (SHA-256)
    pub thumbprint: String,
    /// Certificate subject
    pub subject: String,
    /// Certificate issuer
    pub issuer: String,
    /// Days until expiry
    pub days_until_expiry: i64,
    /// Serial number
    pub serial: String,
    /// Whether this certificate is different from the reference
    pub is_different: bool,
    /// Specific differences from reference certificate
    pub differences: Vec<CertDifference>,
    /// Error if certificate couldn't be retrieved
    pub error: Option<String>,
}

/// Specific difference between certificates
#[derive(Debug, Clone, Serialize)]
pub enum CertDifference {
    /// Different thumbprint (fingerprint)
    Thumbprint { expected: String, actual: String },
    /// Different subject
    Subject { expected: String, actual: String },
    /// Different issuer
    Issuer { expected: String, actual: String },
    /// Different expiry
    Expiry { expected: i64, actual: i64 },
    /// Different serial number
    Serial { expected: String, actual: String },
}

impl CertDifference {
    /// Get a human-readable description of the difference
    pub fn description(&self) -> String {
        match self {
            CertDifference::Thumbprint { expected, actual } => {
                format!(
                    "Thumbprint differs: expected {}..., got {}...",
                    &expected[..16.min(expected.len())],
                    &actual[..16.min(actual.len())]
                )
            }
            CertDifference::Subject { expected, actual } => {
                format!("Subject differs: expected '{}', got '{}'", expected, actual)
            }
            CertDifference::Issuer { expected, actual } => {
                format!("Issuer differs: expected '{}', got '{}'", expected, actual)
            }
            CertDifference::Expiry { expected, actual } => {
                format!(
                    "Expiry differs: expected {} days, got {} days",
                    expected, actual
                )
            }
            CertDifference::Serial { expected, actual } => {
                format!("Serial differs: expected '{}', got '{}'", expected, actual)
            }
        }
    }

    /// Get short field name for the difference
    pub fn field_name(&self) -> &'static str {
        match self {
            CertDifference::Thumbprint { .. } => "Thumbprint",
            CertDifference::Subject { .. } => "Subject",
            CertDifference::Issuer { .. } => "Issuer",
            CertDifference::Expiry { .. } => "Expiry",
            CertDifference::Serial { .. } => "Serial",
        }
    }
}

/// Full comparison results across all IPs
#[derive(Debug, Clone, Default, Serialize)]
pub struct CertComparison {
    /// Reference IP (the one the user selected)
    pub reference_ip: Option<IpAddr>,
    /// All comparison entries
    pub entries: Vec<CertComparisonEntry>,
    /// Whether there are any differences
    pub has_differences: bool,
    /// Summary message
    pub summary: String,
}

impl CertComparison {
    /// Create a new empty comparison
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the reference IP and its certificate info
    pub fn set_reference(
        &mut self,
        ip: IpAddr,
        thumbprint: String,
        subject: String,
        issuer: String,
        days_until_expiry: i64,
        serial: String,
    ) {
        self.reference_ip = Some(ip);
        self.entries.push(CertComparisonEntry {
            ip,
            thumbprint,
            subject,
            issuer,
            days_until_expiry,
            serial,
            is_different: false,
            differences: vec![],
            error: None,
        });
    }

    /// Add a comparison entry for another IP
    pub fn add_entry(&mut self, entry: CertComparisonEntry) {
        if entry.is_different {
            self.has_differences = true;
        }
        self.entries.push(entry);
    }

    /// Compare a certificate against the reference
    pub fn compare_with_reference(
        &self,
        ip: IpAddr,
        thumbprint: &str,
        subject: &str,
        issuer: &str,
        days_until_expiry: i64,
        serial: &str,
    ) -> CertComparisonEntry {
        let reference = self.entries.first();

        let mut differences = Vec::new();
        let mut is_different = false;

        if let Some(ref_entry) = reference {
            if ref_entry.thumbprint != thumbprint {
                differences.push(CertDifference::Thumbprint {
                    expected: ref_entry.thumbprint.clone(),
                    actual: thumbprint.to_string(),
                });
                is_different = true;
            }
            if ref_entry.subject != subject {
                differences.push(CertDifference::Subject {
                    expected: ref_entry.subject.clone(),
                    actual: subject.to_string(),
                });
                is_different = true;
            }
            if ref_entry.issuer != issuer {
                differences.push(CertDifference::Issuer {
                    expected: ref_entry.issuer.clone(),
                    actual: issuer.to_string(),
                });
                is_different = true;
            }
            if ref_entry.days_until_expiry != days_until_expiry {
                differences.push(CertDifference::Expiry {
                    expected: ref_entry.days_until_expiry,
                    actual: days_until_expiry,
                });
                is_different = true;
            }
            if ref_entry.serial != serial {
                differences.push(CertDifference::Serial {
                    expected: ref_entry.serial.clone(),
                    actual: serial.to_string(),
                });
                is_different = true;
            }
        }

        CertComparisonEntry {
            ip,
            thumbprint: thumbprint.to_string(),
            subject: subject.to_string(),
            issuer: issuer.to_string(),
            days_until_expiry,
            serial: serial.to_string(),
            is_different,
            differences,
            error: None,
        }
    }

    /// Create an error entry for an IP that failed
    pub fn error_entry(ip: IpAddr, error: String) -> CertComparisonEntry {
        CertComparisonEntry {
            ip,
            thumbprint: String::new(),
            subject: String::new(),
            issuer: String::new(),
            days_until_expiry: 0,
            serial: String::new(),
            is_different: true,
            differences: vec![],
            error: Some(error),
        }
    }

    /// Generate summary message
    pub fn generate_summary(&mut self) {
        let total = self.entries.len();
        let different = self.entries.iter().filter(|e| e.is_different).count();
        let errors = self.entries.iter().filter(|e| e.error.is_some()).count();

        if total <= 1 {
            self.summary = "Single IP - no comparison available".to_string();
        } else if different == 0 {
            self.summary = format!("All {} IPs return identical certificates", total);
        } else if errors > 0 && different == errors {
            self.summary = format!(
                "{} of {} IPs had errors, {} returned matching certificates",
                errors,
                total,
                total - errors
            );
        } else {
            self.summary = format!(
                "Certificate differences detected: {} of {} IPs differ",
                different, total
            );
        }
    }
}
