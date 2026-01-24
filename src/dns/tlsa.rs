//! DANE/TLSA record checking and validation

use crate::certificate::CertificateInfo;
use crate::dns::records::{TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage};
use crate::error::{Result, SslToolkitError};
use sha2::{Digest, Sha256, Sha512};

/// DANE validation result
#[derive(Debug, Clone)]
pub struct DaneValidationResult {
    pub is_valid: bool,
    pub matching_record: Option<TlsaRecord>,
    pub error: Option<String>,
}

/// Check TLSA records for a domain and port
pub async fn lookup_tlsa_records(domain: &str, port: u16) -> Result<Vec<TlsaRecord>> {
    // TLSA records are at _port._protocol.domain
    let tlsa_domain = format!("_{}._tcp.{}", port, domain);

    // This would require raw DNS queries to get TLSA records
    // hickory-resolver doesn't have direct TLSA support
    // For now, return empty and note that this needs implementation with hickory-proto

    tracing::debug!("Looking up TLSA records for {}", tlsa_domain);

    // Placeholder - would use hickory_proto for actual TLSA queries
    Ok(Vec::new())
}

/// Validate a certificate against TLSA records
pub fn validate_certificate_against_tlsa(
    cert: &CertificateInfo,
    tlsa_records: &[TlsaRecord],
) -> DaneValidationResult {
    if tlsa_records.is_empty() {
        return DaneValidationResult {
            is_valid: false,
            matching_record: None,
            error: Some("No TLSA records found".to_string()),
        };
    }

    // Get certificate data for comparison
    let cert_der = match &cert.raw_pem {
        Some(pem) => {
            match pem::parse(pem) {
                Ok(p) => p.into_contents(),
                Err(e) => {
                    return DaneValidationResult {
                        is_valid: false,
                        matching_record: None,
                        error: Some(format!("Failed to parse certificate PEM: {}", e)),
                    }
                }
            }
        }
        None => {
            return DaneValidationResult {
                is_valid: false,
                matching_record: None,
                error: Some("No certificate data available".to_string()),
            }
        }
    };

    for record in tlsa_records {
        if validate_single_tlsa(&cert_der, record) {
            return DaneValidationResult {
                is_valid: true,
                matching_record: Some(record.clone()),
                error: None,
            };
        }
    }

    DaneValidationResult {
        is_valid: false,
        matching_record: None,
        error: Some("Certificate does not match any TLSA record".to_string()),
    }
}

fn validate_single_tlsa(cert_der: &[u8], record: &TlsaRecord) -> bool {
    // Get the data to compare based on selector
    let data = match record.selector {
        TlsaSelector::FullCertificate => cert_der.to_vec(),
        TlsaSelector::SubjectPublicKeyInfo => {
            // Extract SPKI from certificate
            // This is simplified - full implementation needs proper ASN.1 parsing
            extract_spki(cert_der).unwrap_or_default()
        }
    };

    // Calculate hash based on matching type
    let hash = match record.matching_type {
        TlsaMatchingType::Exact => hex::encode(&data),
        TlsaMatchingType::Sha256 => hex::encode(Sha256::digest(&data)),
        TlsaMatchingType::Sha512 => hex::encode(Sha512::digest(&data)),
    };

    // Compare with record data
    hash.eq_ignore_ascii_case(&record.certificate_data)
}

fn extract_spki(cert_der: &[u8]) -> Option<Vec<u8>> {
    // Parse certificate and extract SubjectPublicKeyInfo
    // This is a simplified extraction - production code should use x509-parser

    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let spki = cert.public_key();

    // Encode SPKI back to DER
    // The raw data from the certificate should work
    Some(spki.raw.to_vec())
}

/// Generate TLSA record data for a certificate
pub fn generate_tlsa_record(
    cert: &CertificateInfo,
    usage: TlsaUsage,
    selector: TlsaSelector,
    matching_type: TlsaMatchingType,
) -> Result<TlsaRecord> {
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

    let data = match selector {
        TlsaSelector::FullCertificate => cert_der.clone(),
        TlsaSelector::SubjectPublicKeyInfo => {
            extract_spki(&cert_der).ok_or_else(|| {
                SslToolkitError::Certificate("Failed to extract SPKI".to_string())
            })?
        }
    };

    let certificate_data = match matching_type {
        TlsaMatchingType::Exact => hex::encode(&data),
        TlsaMatchingType::Sha256 => hex::encode(Sha256::digest(&data)),
        TlsaMatchingType::Sha512 => hex::encode(Sha512::digest(&data)),
    };

    Ok(TlsaRecord {
        usage,
        selector,
        matching_type,
        certificate_data,
    })
}

/// Format TLSA record for DNS zone file
pub fn format_tlsa_for_zone(domain: &str, port: u16, record: &TlsaRecord) -> String {
    format!(
        "_{}._tcp.{} IN TLSA {} {} {} {}",
        port,
        domain,
        record.usage as u8,
        record.selector as u8,
        record.matching_type as u8,
        record.certificate_data
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_tlsa_for_zone() {
        let record = TlsaRecord {
            usage: TlsaUsage::DomainIssuedCertificate,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching_type: TlsaMatchingType::Sha256,
            certificate_data: "abc123".to_string(),
        };

        let formatted = format_tlsa_for_zone("example.com", 443, &record);
        assert!(formatted.contains("_443._tcp.example.com"));
        assert!(formatted.contains("TLSA 3 1 1"));
    }
}
