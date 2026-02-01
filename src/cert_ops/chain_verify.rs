//! Certificate chain validation
//!
//! Validates chain integrity: issuer→subject chaining, signature correctness,
//! and time validity. This does NOT validate trust anchoring (no root store).

use crate::utils::CertFileError;
use chrono::Utc;
use x509_parser::prelude::*;

/// Result of chain validation
#[derive(Debug)]
pub struct ChainValidationResult {
    /// Whether the overall chain is valid
    pub is_valid: bool,
    /// Individual step results
    pub steps: Vec<ChainStep>,
    /// Summary message
    pub summary: String,
}

/// A single step in chain validation
#[derive(Debug)]
pub struct ChainStep {
    pub description: String,
    pub passed: bool,
    pub details: Option<String>,
}

/// Validate a certificate chain for integrity
///
/// Checks:
/// 1. Each certificate's issuer matches the next certificate's subject
/// 2. Each certificate's signature is valid (signed by the next cert in chain)
/// 3. All certificates are within their validity period
/// 4. Optionally checks hostname against the leaf certificate
///
/// Note: This validates chain *integrity*, not trust anchoring.
/// The chain is not checked against a root certificate store.
pub fn verify_chain(
    certs_der: &[Vec<u8>],
    hostname: Option<&str>,
) -> Result<ChainValidationResult, CertFileError> {
    if certs_der.is_empty() {
        return Err(CertFileError::ChainError {
            message: "Empty certificate chain".to_string(),
        });
    }

    let mut steps = Vec::new();
    let mut all_valid = true;
    let now = Utc::now();

    // Parse all certificates
    let parsed: Vec<X509Certificate> = certs_der
        .iter()
        .enumerate()
        .map(|(i, der)| {
            X509Certificate::from_der(der)
                .map(|(_, cert)| cert)
                .map_err(|e| CertFileError::ChainError {
                    message: format!("Failed to parse certificate #{}: {:?}", i, e),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Check hostname against leaf certificate
    if let Some(host) = hostname {
        let leaf = &parsed[0];
        let checker = crate::checks::CertificateChecker::new();
        let leaf_info = checker
            .parse_certificate(certs_der[0].as_slice())
            .map_err(|e| CertFileError::ChainError {
                message: format!("Failed to parse leaf certificate: {}", e),
            })?;

        let matches = leaf_info.matches_hostname(host);
        steps.push(ChainStep {
            description: format!("Hostname '{}' matches leaf certificate", host),
            passed: matches,
            details: if matches {
                None
            } else {
                Some(format!(
                    "Certificate subject: {}, SANs: {:?}",
                    leaf.subject(),
                    leaf_info.san
                ))
            },
        });
        if !matches {
            all_valid = false;
        }
    }

    // Check time validity for each certificate
    for (i, cert) in parsed.iter().enumerate() {
        let label = if i == 0 {
            "Leaf".to_string()
        } else if i == parsed.len() - 1 {
            "Root/Top".to_string()
        } else {
            format!("Intermediate #{}", i)
        };

        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        let now_ts = now.timestamp();

        let time_valid = now_ts >= not_before && now_ts <= not_after;
        steps.push(ChainStep {
            description: format!("{} certificate is within validity period", label),
            passed: time_valid,
            details: if time_valid {
                None
            } else if now_ts < not_before {
                Some("Certificate is not yet valid".to_string())
            } else {
                Some("Certificate has expired".to_string())
            },
        });
        if !time_valid {
            all_valid = false;
        }
    }

    // Check issuer→subject chaining
    for i in 0..parsed.len().saturating_sub(1) {
        let child = &parsed[i];
        let parent = &parsed[i + 1];

        let issuer_matches = child.issuer() == parent.subject();
        let child_label = if i == 0 { "Leaf" } else { "Intermediate" };

        steps.push(ChainStep {
            description: format!(
                "{} certificate issuer matches next certificate subject",
                child_label
            ),
            passed: issuer_matches,
            details: if issuer_matches {
                None
            } else {
                Some(format!(
                    "Issuer: {}, Expected subject: {}",
                    child.issuer(),
                    parent.subject()
                ))
            },
        });
        if !issuer_matches {
            all_valid = false;
        }

        // Verify signature
        let sig_valid = child.verify_signature(Some(parent.public_key())).is_ok();
        steps.push(ChainStep {
            description: format!("{} certificate signature is valid", child_label),
            passed: sig_valid,
            details: if sig_valid {
                None
            } else {
                Some("Signature verification failed".to_string())
            },
        });
        if !sig_valid {
            all_valid = false;
        }
    }

    // Check if top cert is self-signed (root)
    if parsed.len() > 1 {
        let top = parsed.last().unwrap();
        let is_self_signed = top.subject() == top.issuer();
        steps.push(ChainStep {
            description: "Top certificate is self-signed (root)".to_string(),
            passed: is_self_signed,
            details: if is_self_signed {
                None
            } else {
                Some("Chain may be incomplete (top cert is not self-signed)".to_string())
            },
        });
        // Not marking as invalid - incomplete chain is a warning, not failure
    }

    let summary = if all_valid {
        format!(
            "Chain validation passed ({} certificate{})",
            parsed.len(),
            if parsed.len() == 1 { "" } else { "s" }
        )
    } else {
        let failed = steps.iter().filter(|s| !s.passed).count();
        format!(
            "Chain validation failed: {} issue{} found",
            failed,
            if failed == 1 { "" } else { "s" }
        )
    };

    Ok(ChainValidationResult {
        is_valid: all_valid,
        steps,
        summary,
    })
}
