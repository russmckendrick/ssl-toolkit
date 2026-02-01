//! Certificate file reading and format detection
//!
//! Auto-detects PEM, DER, and PKCS#12 formats and extracts DER-encoded certificates.

use crate::utils::CertFileError;
use std::path::Path;
use x509_parser::prelude::*;

/// Detected certificate file format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedFormat {
    Pem,
    Der,
    Pkcs12,
}

impl std::fmt::Display for DetectedFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectedFormat::Pem => write!(f, "PEM"),
            DetectedFormat::Der => write!(f, "DER"),
            DetectedFormat::Pkcs12 => write!(f, "PKCS#12"),
        }
    }
}

/// Detect the format of a certificate file by inspecting its contents
pub fn detect_format(path: &Path) -> Result<DetectedFormat, CertFileError> {
    let data = std::fs::read(path).map_err(|e| CertFileError::FileReadError {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;

    detect_format_from_bytes(&data)
}

/// Detect format from raw bytes
pub fn detect_format_from_bytes(data: &[u8]) -> Result<DetectedFormat, CertFileError> {
    // Check for PEM markers
    if let Ok(text) = std::str::from_utf8(data) {
        if text.contains("-----BEGIN ") {
            return Ok(DetectedFormat::Pem);
        }
    }

    // Check for PKCS#12 magic: ASN.1 SEQUENCE containing pkcs7-data OID
    if data.len() > 4 && data[0] == 0x30 && is_likely_pkcs12(data) {
        return Ok(DetectedFormat::Pkcs12);
    }

    // Try parsing as DER X.509
    if X509Certificate::from_der(data).is_ok() {
        return Ok(DetectedFormat::Der);
    }

    // If none matched but starts with 0x30 (ASN.1 SEQUENCE), assume DER
    if !data.is_empty() && data[0] == 0x30 {
        return Ok(DetectedFormat::Der);
    }

    Err(CertFileError::UnsupportedFormat {
        format: "unknown (could not detect PEM, DER, or PKCS#12)".to_string(),
    })
}

/// Heuristic to distinguish PKCS#12 from plain DER certificate.
fn is_likely_pkcs12(data: &[u8]) -> bool {
    // Look for the pkcs7-data OID: 06 09 2a 86 48 86 f7 0d 01 07 01
    let pkcs7_data_oid: [u8; 11] = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
    ];
    let search_len = data.len().min(50);
    data[..search_len]
        .windows(pkcs7_data_oid.len())
        .any(|w| w == pkcs7_data_oid)
}

/// Read certificates from a file, returning DER-encoded certificate bytes.
pub fn read_certificates(
    path: &Path,
    password: Option<&str>,
) -> Result<Vec<Vec<u8>>, CertFileError> {
    let data = std::fs::read(path).map_err(|e| CertFileError::FileReadError {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;

    let format = detect_format_from_bytes(&data)?;

    match format {
        DetectedFormat::Pem => read_pem_certificates(&data, path),
        DetectedFormat::Der => read_der_certificate(&data, path),
        DetectedFormat::Pkcs12 => read_pkcs12_certificates(&data, path, password),
    }
}

/// Read all CERTIFICATE blocks from PEM data
fn read_pem_certificates(data: &[u8], path: &Path) -> Result<Vec<Vec<u8>>, CertFileError> {
    let pems = ::pem::parse_many(data).map_err(|e| CertFileError::FileReadError {
        path: path.display().to_string(),
        message: format!("Failed to parse PEM: {}", e),
    })?;

    let certs: Vec<Vec<u8>> = pems
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| p.into_contents())
        .collect();

    if certs.is_empty() {
        return Err(CertFileError::FileReadError {
            path: path.display().to_string(),
            message: "No CERTIFICATE blocks found in PEM file".to_string(),
        });
    }

    Ok(certs)
}

/// Read a single DER-encoded certificate
fn read_der_certificate(data: &[u8], path: &Path) -> Result<Vec<Vec<u8>>, CertFileError> {
    X509Certificate::from_der(data).map_err(|e| CertFileError::FileReadError {
        path: path.display().to_string(),
        message: format!("Failed to parse DER certificate: {:?}", e),
    })?;

    Ok(vec![data.to_vec()])
}

/// Read certificates from a PKCS#12 container
fn read_pkcs12_certificates(
    data: &[u8],
    path: &Path,
    password: Option<&str>,
) -> Result<Vec<Vec<u8>>, CertFileError> {
    let pwd = password.unwrap_or("");

    let keystore =
        p12_keystore::KeyStore::from_pkcs12(data, pwd).map_err(|e| CertFileError::Pkcs12Error {
            message: format!("Failed to parse PKCS#12 from {}: {}", path.display(), e),
        })?;

    let mut certs = Vec::new();

    // Extract certificates from all entries
    for (_alias, entry) in keystore.entries() {
        match entry {
            p12_keystore::KeyStoreEntry::PrivateKeyChain(chain) => {
                for cert in chain.chain() {
                    certs.push(cert.as_der().to_vec());
                }
            }
            p12_keystore::KeyStoreEntry::Certificate(cert) => {
                certs.push(cert.as_der().to_vec());
            }
        }
    }

    if certs.is_empty() {
        return Err(CertFileError::Pkcs12Error {
            message: format!("No certificates found in PKCS#12 file: {}", path.display()),
        });
    }

    Ok(certs)
}

/// Read raw PEM blocks of any type from a file
pub fn read_pem_blocks(path: &Path) -> Result<Vec<::pem::Pem>, CertFileError> {
    let data = std::fs::read(path).map_err(|e| CertFileError::FileReadError {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;

    ::pem::parse_many(data).map_err(|e| CertFileError::FileReadError {
        path: path.display().to_string(),
        message: format!("Failed to parse PEM: {}", e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pem_format() {
        let pem_data =
            b"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----\n";
        assert_eq!(
            detect_format_from_bytes(pem_data).unwrap(),
            DetectedFormat::Pem
        );
    }

    #[test]
    fn test_detect_unknown_format() {
        let garbage = b"this is not a certificate";
        assert!(detect_format_from_bytes(garbage).is_err());
    }
}
