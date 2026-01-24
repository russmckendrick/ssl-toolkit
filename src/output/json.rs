//! JSON output formatting

use crate::certificate::{CertificateChain, SecurityGrade, SslCheckResult};
use crate::dns::DnsInfo;
use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Complete SSL check result for JSON output
#[derive(Serialize)]
pub struct JsonOutput {
    pub domain: String,
    pub check_time: DateTime<Utc>,
    pub certificate: Option<JsonCertificate>,
    pub chain: Option<JsonChain>,
    pub security_grade: Option<JsonSecurityGrade>,
    pub dns: Option<DnsInfo>,
    pub errors: Vec<String>,
}

#[derive(Serialize)]
pub struct JsonCertificate {
    pub version: u32,
    pub serial_number: String,
    pub subject: JsonName,
    pub issuer: JsonName,
    pub not_before: String,
    pub not_after: String,
    pub days_until_expiry: i64,
    pub signature_algorithm: String,
    pub key_algorithm: String,
    pub key_size: u32,
    pub subject_alt_names: Vec<String>,
    pub is_valid: bool,
    pub trust_status: String,
    pub ocsp_status: Option<String>,
    pub ct_logged: bool,
    pub fingerprint_sha256: String,
}

#[derive(Serialize)]
pub struct JsonName {
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub country: Option<String>,
}

#[derive(Serialize)]
pub struct JsonChain {
    pub length: usize,
    pub is_complete: bool,
    pub root_in_store: bool,
    pub certificates: Vec<JsonChainCert>,
}

#[derive(Serialize)]
pub struct JsonChainCert {
    pub subject: String,
    pub issuer: String,
    pub not_after: String,
    pub is_ca: bool,
}

#[derive(Serialize)]
pub struct JsonSecurityGrade {
    pub grade: String,
    pub score: u8,
    pub factors: Vec<JsonGradeFactor>,
}

#[derive(Serialize)]
pub struct JsonGradeFactor {
    pub name: String,
    pub status: String,
    pub points: i32,
    pub max_points: i32,
    pub description: String,
}

/// Convert SSL check result to JSON output format
pub fn to_json_output(
    domain: &str,
    chain: &CertificateChain,
    grade: Option<&SecurityGrade>,
    dns: Option<&DnsInfo>,
    errors: &[String],
) -> JsonOutput {
    let certificate = chain.leaf().map(|cert| JsonCertificate {
        version: cert.version,
        serial_number: cert.serial_number.clone(),
        subject: JsonName {
            common_name: cert.subject.common_name.clone(),
            organization: cert.subject.organization.clone(),
            country: cert.subject.country.clone(),
        },
        issuer: JsonName {
            common_name: cert.issuer.common_name.clone(),
            organization: cert.issuer.organization.clone(),
            country: cert.issuer.country.clone(),
        },
        not_before: cert.not_before.to_rfc3339(),
        not_after: cert.not_after.to_rfc3339(),
        days_until_expiry: cert.days_until_expiry,
        signature_algorithm: cert.signature_algorithm.clone(),
        key_algorithm: cert.key_algorithm.to_string(),
        key_size: cert.key_size,
        subject_alt_names: cert.subject_alt_names.clone(),
        is_valid: cert.is_valid(),
        trust_status: cert.trust_status.to_string(),
        ocsp_status: cert.ocsp_status.as_ref().map(|s| s.to_string()),
        ct_logged: cert.ct_logged,
        fingerprint_sha256: cert.fingerprint_sha256.clone(),
    });

    let json_chain = Some(JsonChain {
        length: chain.chain_length,
        is_complete: chain.is_complete,
        root_in_store: chain.root_in_store,
        certificates: chain
            .certificates
            .iter()
            .map(|c| JsonChainCert {
                subject: c.subject.common_name.clone().unwrap_or_default(),
                issuer: c.issuer.common_name.clone().unwrap_or_default(),
                not_after: c.not_after.to_rfc3339(),
                is_ca: c.is_ca,
            })
            .collect(),
    });

    let security_grade = grade.map(|g| JsonSecurityGrade {
        grade: g.display(),
        score: g.score,
        factors: g
            .factors
            .iter()
            .map(|f| JsonGradeFactor {
                name: f.name.clone(),
                status: f.status.to_string(),
                points: f.points,
                max_points: f.max_points,
                description: f.description.clone(),
            })
            .collect(),
    });

    JsonOutput {
        domain: domain.to_string(),
        check_time: Utc::now(),
        certificate,
        chain: json_chain,
        security_grade,
        dns: dns.cloned(),
        errors: errors.to_vec(),
    }
}

/// Output JSON to stdout
pub fn print_json<T: Serialize>(data: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| crate::error::SslToolkitError::Parse(e.to_string()))?;
    println!("{}", json);
    Ok(())
}

/// Output JSON to file
pub fn write_json_file<T: Serialize>(data: &T, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| crate::error::SslToolkitError::Parse(e.to_string()))?;

    let mut file = File::create(path)
        .map_err(|e| crate::error::SslToolkitError::File(e.to_string()))?;

    file.write_all(json.as_bytes())
        .map_err(|e| crate::error::SslToolkitError::File(e.to_string()))?;

    Ok(())
}
