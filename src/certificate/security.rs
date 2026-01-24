//! Security scoring and grading for SSL certificates

use crate::certificate::info::{CertificateChain, CertificateInfo, KeyAlgorithm, OcspStatus, TrustStatus};
use serde::{Deserialize, Serialize};

/// Security grade for a certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGrade {
    pub grade: char,
    pub plus: bool,
    pub score: u8,
    pub factors: Vec<GradeFactor>,
}

impl SecurityGrade {
    pub fn display(&self) -> String {
        if self.plus {
            format!("{}+", self.grade)
        } else {
            self.grade.to_string()
        }
    }
}

/// Individual factor contributing to the security grade
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradeFactor {
    pub name: String,
    pub status: FactorStatus,
    pub points: i32,
    pub max_points: i32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FactorStatus {
    Pass,
    Warning,
    Fail,
    NotApplicable,
}

impl std::fmt::Display for FactorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FactorStatus::Pass => write!(f, "Pass"),
            FactorStatus::Warning => write!(f, "Warning"),
            FactorStatus::Fail => write!(f, "Fail"),
            FactorStatus::NotApplicable => write!(f, "N/A"),
        }
    }
}

/// Calculate security grade for a certificate chain
pub fn calculate_security_grade(
    chain: &CertificateChain,
    has_hsts: bool,
    has_caa: bool,
) -> SecurityGrade {
    let mut factors = Vec::new();
    let mut total_points: i32 = 0;
    let mut max_points: i32 = 0;

    // Get the leaf certificate
    let leaf = match chain.leaf() {
        Some(c) => c,
        None => {
            return SecurityGrade {
                grade: 'F',
                plus: false,
                score: 0,
                factors: vec![GradeFactor {
                    name: "Certificate".to_string(),
                    status: FactorStatus::Fail,
                    points: 0,
                    max_points: 100,
                    description: "No certificate found".to_string(),
                }],
            }
        }
    };

    // Factor 1: Key Size (20 points max)
    let key_factor = check_key_size(leaf);
    total_points += key_factor.points;
    max_points += key_factor.max_points;
    factors.push(key_factor);

    // Factor 2: Signature Algorithm (15 points max)
    let sig_factor = check_signature_algorithm(leaf);
    total_points += sig_factor.points;
    max_points += sig_factor.max_points;
    factors.push(sig_factor);

    // Factor 3: Certificate Validity (15 points max)
    let validity_factor = check_validity(leaf);
    total_points += validity_factor.points;
    max_points += validity_factor.max_points;
    factors.push(validity_factor);

    // Factor 4: Chain Completeness (10 points max)
    let chain_factor = check_chain(chain);
    total_points += chain_factor.points;
    max_points += chain_factor.max_points;
    factors.push(chain_factor);

    // Factor 5: OCSP Status (10 points max)
    let ocsp_factor = check_ocsp(leaf);
    total_points += ocsp_factor.points;
    max_points += ocsp_factor.max_points;
    factors.push(ocsp_factor);

    // Factor 6: Certificate Transparency (10 points max)
    let ct_factor = check_ct(leaf);
    total_points += ct_factor.points;
    max_points += ct_factor.max_points;
    factors.push(ct_factor);

    // Factor 7: HSTS (10 points max)
    let hsts_factor = check_hsts(has_hsts);
    total_points += hsts_factor.points;
    max_points += hsts_factor.max_points;
    factors.push(hsts_factor);

    // Factor 8: CAA Records (5 points max)
    let caa_factor = check_caa(has_caa);
    total_points += caa_factor.points;
    max_points += caa_factor.max_points;
    factors.push(caa_factor);

    // Factor 9: Expiry Warning (5 points max)
    let expiry_factor = check_expiry_warning(leaf);
    total_points += expiry_factor.points;
    max_points += expiry_factor.max_points;
    factors.push(expiry_factor);

    // Calculate percentage score
    let score = if max_points > 0 {
        ((total_points as f64 / max_points as f64) * 100.0) as u8
    } else {
        0
    };

    // Determine grade
    let (grade, plus) = score_to_grade(score, &factors);

    SecurityGrade {
        grade,
        plus,
        score,
        factors,
    }
}

fn check_key_size(cert: &CertificateInfo) -> GradeFactor {
    let (status, points, description) = match &cert.key_algorithm {
        KeyAlgorithm::Rsa(bits) => {
            if *bits >= 4096 {
                (FactorStatus::Pass, 20, format!("RSA {} bits (excellent)", bits))
            } else if *bits >= 2048 {
                (FactorStatus::Pass, 18, format!("RSA {} bits (good)", bits))
            } else if *bits >= 1024 {
                (FactorStatus::Warning, 10, format!("RSA {} bits (weak)", bits))
            } else {
                (FactorStatus::Fail, 0, format!("RSA {} bits (insecure)", bits))
            }
        }
        KeyAlgorithm::Ecdsa(curve) => {
            if curve.contains("521") {
                (FactorStatus::Pass, 20, format!("ECDSA {} (excellent)", curve))
            } else if curve.contains("384") {
                (FactorStatus::Pass, 20, format!("ECDSA {} (excellent)", curve))
            } else if curve.contains("256") {
                (FactorStatus::Pass, 18, format!("ECDSA {} (good)", curve))
            } else {
                (FactorStatus::Warning, 12, format!("ECDSA {} (unknown curve)", curve))
            }
        }
        KeyAlgorithm::Ed25519 => (FactorStatus::Pass, 20, "Ed25519 (excellent)".to_string()),
        KeyAlgorithm::Ed448 => (FactorStatus::Pass, 20, "Ed448 (excellent)".to_string()),
        KeyAlgorithm::Dsa(bits) => {
            (FactorStatus::Warning, 5, format!("DSA {} bits (legacy)", bits))
        }
        KeyAlgorithm::Unknown(s) => {
            (FactorStatus::Warning, 10, format!("Unknown algorithm: {}", s))
        }
    };

    GradeFactor {
        name: "Key Size".to_string(),
        status,
        points,
        max_points: 20,
        description,
    }
}

fn check_signature_algorithm(cert: &CertificateInfo) -> GradeFactor {
    let sig = cert.signature_algorithm.to_lowercase();

    let (status, points, description) = if sig.contains("sha512") || sig.contains("sha-512") {
        (FactorStatus::Pass, 15, "SHA-512 (excellent)".to_string())
    } else if sig.contains("sha384") || sig.contains("sha-384") {
        (FactorStatus::Pass, 15, "SHA-384 (excellent)".to_string())
    } else if sig.contains("sha256") || sig.contains("sha-256") {
        (FactorStatus::Pass, 15, "SHA-256 (good)".to_string())
    } else if sig.contains("sha1") || sig.contains("sha-1") {
        (FactorStatus::Fail, 0, "SHA-1 (deprecated, insecure)".to_string())
    } else if sig.contains("md5") {
        (FactorStatus::Fail, 0, "MD5 (insecure)".to_string())
    } else if sig.contains("ed25519") || sig.contains("ed448") {
        (FactorStatus::Pass, 15, "EdDSA (excellent)".to_string())
    } else {
        (FactorStatus::Warning, 10, format!("Unknown: {}", cert.signature_algorithm))
    };

    GradeFactor {
        name: "Signature Algorithm".to_string(),
        status,
        points,
        max_points: 15,
        description,
    }
}

fn check_validity(cert: &CertificateInfo) -> GradeFactor {
    let (status, points, description) = match cert.trust_status {
        TrustStatus::Trusted => (FactorStatus::Pass, 15, "Certificate is valid and trusted".to_string()),
        TrustStatus::SelfSigned => (FactorStatus::Warning, 5, "Self-signed certificate".to_string()),
        TrustStatus::Expired => (FactorStatus::Fail, 0, "Certificate has expired".to_string()),
        TrustStatus::NotYetValid => (FactorStatus::Fail, 0, "Certificate is not yet valid".to_string()),
        TrustStatus::Revoked => (FactorStatus::Fail, 0, "Certificate has been revoked".to_string()),
        TrustStatus::Untrusted => (FactorStatus::Warning, 5, "Certificate is not trusted".to_string()),
        TrustStatus::Unknown => (FactorStatus::Warning, 10, "Trust status unknown".to_string()),
    };

    GradeFactor {
        name: "Certificate Validity".to_string(),
        status,
        points,
        max_points: 15,
        description,
    }
}

fn check_chain(chain: &CertificateChain) -> GradeFactor {
    let (status, points, description) = if chain.is_complete && chain.root_in_store {
        (FactorStatus::Pass, 10, "Complete chain with trusted root".to_string())
    } else if chain.is_complete {
        (FactorStatus::Warning, 7, "Complete chain but root not in trust store".to_string())
    } else if chain.chain_length > 1 {
        (FactorStatus::Warning, 5, "Incomplete chain (missing intermediates or root)".to_string())
    } else {
        (FactorStatus::Fail, 0, "No certificate chain provided".to_string())
    };

    GradeFactor {
        name: "Certificate Chain".to_string(),
        status,
        points,
        max_points: 10,
        description,
    }
}

fn check_ocsp(cert: &CertificateInfo) -> GradeFactor {
    let (status, points, description) = match &cert.ocsp_status {
        Some(OcspStatus::Good) => {
            if cert.ocsp_stapling {
                (FactorStatus::Pass, 10, "OCSP Good with stapling enabled".to_string())
            } else {
                (FactorStatus::Pass, 8, "OCSP Good (no stapling)".to_string())
            }
        }
        Some(OcspStatus::Revoked { .. }) => {
            (FactorStatus::Fail, 0, "Certificate revoked via OCSP".to_string())
        }
        Some(OcspStatus::Unknown) => {
            (FactorStatus::Warning, 5, "OCSP status unknown".to_string())
        }
        Some(OcspStatus::Error(e)) => {
            (FactorStatus::Warning, 5, format!("OCSP check failed: {}", e))
        }
        None => {
            if cert.authority_info_access.as_ref().map(|a| !a.ocsp_responders.is_empty()).unwrap_or(false) {
                (FactorStatus::Warning, 5, "OCSP not checked".to_string())
            } else {
                (FactorStatus::NotApplicable, 5, "No OCSP responder configured".to_string())
            }
        }
    };

    GradeFactor {
        name: "OCSP Status".to_string(),
        status,
        points,
        max_points: 10,
        description,
    }
}

fn check_ct(cert: &CertificateInfo) -> GradeFactor {
    let (status, points, description) = if cert.ct_logged {
        (FactorStatus::Pass, 10, "Certificate logged in CT logs".to_string())
    } else {
        (FactorStatus::Warning, 5, "No CT log presence detected".to_string())
    };

    GradeFactor {
        name: "Certificate Transparency".to_string(),
        status,
        points,
        max_points: 10,
        description,
    }
}

fn check_hsts(has_hsts: bool) -> GradeFactor {
    let (status, points, description) = if has_hsts {
        (FactorStatus::Pass, 10, "HSTS header present".to_string())
    } else {
        (FactorStatus::Warning, 0, "HSTS not configured".to_string())
    };

    GradeFactor {
        name: "HSTS".to_string(),
        status,
        points,
        max_points: 10,
        description,
    }
}

fn check_caa(has_caa: bool) -> GradeFactor {
    let (status, points, description) = if has_caa {
        (FactorStatus::Pass, 5, "CAA records configured".to_string())
    } else {
        (FactorStatus::Warning, 2, "No CAA records found".to_string())
    };

    GradeFactor {
        name: "CAA Records".to_string(),
        status,
        points,
        max_points: 5,
        description,
    }
}

fn check_expiry_warning(cert: &CertificateInfo) -> GradeFactor {
    let (status, points, description) = if cert.days_until_expiry < 0 {
        (FactorStatus::Fail, 0, "Certificate has expired".to_string())
    } else if cert.days_until_expiry <= 7 {
        (FactorStatus::Fail, 1, format!("Expiring in {} days!", cert.days_until_expiry))
    } else if cert.days_until_expiry <= 30 {
        (FactorStatus::Warning, 3, format!("Expiring in {} days", cert.days_until_expiry))
    } else if cert.days_until_expiry <= 60 {
        (FactorStatus::Warning, 4, format!("Expiring in {} days", cert.days_until_expiry))
    } else {
        (FactorStatus::Pass, 5, format!("{} days until expiry", cert.days_until_expiry))
    };

    GradeFactor {
        name: "Expiry Status".to_string(),
        status,
        points,
        max_points: 5,
        description,
    }
}

fn score_to_grade(score: u8, factors: &[GradeFactor]) -> (char, bool) {
    // Check for any critical failures
    let has_critical_fail = factors.iter().any(|f| {
        f.status == FactorStatus::Fail
            && (f.name == "Certificate Validity"
                || f.name == "OCSP Status"
                || f.name == "Signature Algorithm")
    });

    if has_critical_fail {
        return ('F', false);
    }

    // Grade based on score
    match score {
        95..=100 => ('A', true),
        85..=94 => ('A', false),
        75..=84 => ('B', false),
        65..=74 => ('C', false),
        50..=64 => ('D', false),
        _ => ('F', false),
    }
}

/// Generate a summary of the security assessment
pub fn generate_security_summary(grade: &SecurityGrade) -> String {
    let mut summary = format!("Security Grade: {}\n", grade.display());
    summary.push_str(&format!("Score: {}%\n\n", grade.score));

    let passes: Vec<_> = grade.factors.iter().filter(|f| f.status == FactorStatus::Pass).collect();
    let warnings: Vec<_> = grade.factors.iter().filter(|f| f.status == FactorStatus::Warning).collect();
    let fails: Vec<_> = grade.factors.iter().filter(|f| f.status == FactorStatus::Fail).collect();

    if !passes.is_empty() {
        summary.push_str("Passed:\n");
        for f in passes {
            summary.push_str(&format!("  + {}: {}\n", f.name, f.description));
        }
    }

    if !warnings.is_empty() {
        summary.push_str("\nWarnings:\n");
        for f in warnings {
            summary.push_str(&format!("  ! {}: {}\n", f.name, f.description));
        }
    }

    if !fails.is_empty() {
        summary.push_str("\nFailed:\n");
        for f in fails {
            summary.push_str(&format!("  X {}: {}\n", f.name, f.description));
        }
    }

    summary
}
