//! Private key parsing and certificate/key pair matching
//!
//! Supports RSA, EC P-256, and EC P-384 keys in PKCS#8, PKCS#1, and SEC1 formats.

use crate::utils::CertFileError;
use std::path::Path;
use x509_parser::prelude::*;

/// Information about a parsed private key
#[derive(Debug)]
pub struct PrivateKeyInfo {
    /// The SubjectPublicKeyInfo bytes derived from the private key
    pub public_key_spki: Vec<u8>,
    /// Key type description
    pub key_type: String,
}

/// Read and parse a private key from a file (PEM or DER)
pub fn read_private_key(path: &Path) -> Result<PrivateKeyInfo, CertFileError> {
    let data = std::fs::read(path).map_err(|e| CertFileError::FileReadError {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;

    // Try PEM first
    if let Ok(text) = std::str::from_utf8(&data) {
        if text.contains("-----BEGIN ") {
            return parse_pem_private_key(text, path);
        }
    }

    // Try DER PKCS#8
    parse_der_private_key(&data, path)
}

/// Parse a PEM-encoded private key
fn parse_pem_private_key(text: &str, path: &Path) -> Result<PrivateKeyInfo, CertFileError> {
    let pems = ::pem::parse_many(text.as_bytes()).map_err(|e| CertFileError::KeyParseError {
        message: format!("Failed to parse PEM from {}: {}", path.display(), e),
    })?;

    for p in &pems {
        match p.tag() {
            "PRIVATE KEY" => {
                // PKCS#8 format
                return parse_pkcs8_der(p.contents());
            }
            "RSA PRIVATE KEY" => {
                // PKCS#1 RSA format
                return parse_pkcs1_rsa(p.contents());
            }
            "EC PRIVATE KEY" => {
                // SEC1 EC format
                return parse_sec1_ec(p.contents());
            }
            _ => continue,
        }
    }

    Err(CertFileError::KeyParseError {
        message: format!(
            "No recognized private key block found in {}",
            path.display()
        ),
    })
}

/// Parse a DER-encoded private key (try PKCS#8 first, then PKCS#1)
fn parse_der_private_key(data: &[u8], path: &Path) -> Result<PrivateKeyInfo, CertFileError> {
    // Try PKCS#8
    if let Ok(info) = parse_pkcs8_der(data) {
        return Ok(info);
    }

    // Try PKCS#1 RSA
    if let Ok(info) = parse_pkcs1_rsa(data) {
        return Ok(info);
    }

    // Try SEC1 EC
    if let Ok(info) = parse_sec1_ec(data) {
        return Ok(info);
    }

    Err(CertFileError::KeyParseError {
        message: format!("Could not parse DER private key from {}", path.display()),
    })
}

/// Parse a PKCS#8 DER-encoded private key and extract SPKI
fn parse_pkcs8_der(der: &[u8]) -> Result<PrivateKeyInfo, CertFileError> {
    use pkcs8::DecodePrivateKey;

    // Try RSA first
    if let Ok(rsa_key) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
        let public_key = rsa::RsaPublicKey::from(&rsa_key);
        use rsa::pkcs8::EncodePublicKey;
        let spki = public_key
            .to_public_key_der()
            .map_err(|e| CertFileError::KeyParseError {
                message: format!("Failed to encode RSA public key: {}", e),
            })?;
        return Ok(PrivateKeyInfo {
            public_key_spki: spki.as_ref().to_vec(),
            key_type: "RSA (PKCS#8)".to_string(),
        });
    }

    // Try EC P-256
    if let Ok(ec_key) = p256::SecretKey::from_pkcs8_der(der) {
        let public_key = ec_key.public_key();
        use p256::pkcs8::EncodePublicKey;
        let spki = public_key
            .to_public_key_der()
            .map_err(|e| CertFileError::KeyParseError {
                message: format!("Failed to encode EC P-256 public key: {}", e),
            })?;
        return Ok(PrivateKeyInfo {
            public_key_spki: spki.as_ref().to_vec(),
            key_type: "EC P-256 (PKCS#8)".to_string(),
        });
    }

    // Try EC P-384
    if let Ok(ec_key) = p384::SecretKey::from_pkcs8_der(der) {
        let public_key = ec_key.public_key();
        use p384::pkcs8::EncodePublicKey;
        let spki = public_key
            .to_public_key_der()
            .map_err(|e| CertFileError::KeyParseError {
                message: format!("Failed to encode EC P-384 public key: {}", e),
            })?;
        return Ok(PrivateKeyInfo {
            public_key_spki: spki.as_ref().to_vec(),
            key_type: "EC P-384 (PKCS#8)".to_string(),
        });
    }

    Err(CertFileError::KeyParseError {
        message: "Unsupported key type in PKCS#8 container".to_string(),
    })
}

/// Parse a PKCS#1 RSA private key
fn parse_pkcs1_rsa(der: &[u8]) -> Result<PrivateKeyInfo, CertFileError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;

    let rsa_key =
        rsa::RsaPrivateKey::from_pkcs1_der(der).map_err(|e| CertFileError::KeyParseError {
            message: format!("Failed to parse PKCS#1 RSA key: {}", e),
        })?;

    let public_key = rsa::RsaPublicKey::from(&rsa_key);
    let spki = public_key
        .to_public_key_der()
        .map_err(|e| CertFileError::KeyParseError {
            message: format!("Failed to encode RSA public key: {}", e),
        })?;

    Ok(PrivateKeyInfo {
        public_key_spki: spki.as_ref().to_vec(),
        key_type: "RSA (PKCS#1)".to_string(),
    })
}

/// Parse a SEC1 EC private key
fn parse_sec1_ec(der: &[u8]) -> Result<PrivateKeyInfo, CertFileError> {
    use p256::pkcs8::EncodePublicKey;

    // Try P-256 first
    if let Ok(ec_key) = p256::SecretKey::from_sec1_der(der) {
        let public_key = ec_key.public_key();
        let spki = public_key
            .to_public_key_der()
            .map_err(|e| CertFileError::KeyParseError {
                message: format!("Failed to encode EC P-256 public key: {}", e),
            })?;
        return Ok(PrivateKeyInfo {
            public_key_spki: spki.as_ref().to_vec(),
            key_type: "EC P-256 (SEC1)".to_string(),
        });
    }

    // Try P-384
    if let Ok(ec_key) = p384::SecretKey::from_sec1_der(der) {
        let public_key = ec_key.public_key();
        use p384::pkcs8::EncodePublicKey;
        let spki = public_key
            .to_public_key_der()
            .map_err(|e| CertFileError::KeyParseError {
                message: format!("Failed to encode EC P-384 public key: {}", e),
            })?;
        return Ok(PrivateKeyInfo {
            public_key_spki: spki.as_ref().to_vec(),
            key_type: "EC P-384 (SEC1)".to_string(),
        });
    }

    Err(CertFileError::KeyParseError {
        message: "Unsupported EC curve (only P-256 and P-384 are supported)".to_string(),
    })
}

/// Check if a private key matches a certificate by comparing SubjectPublicKeyInfo
pub fn keys_match(cert_der: &[u8], key_info: &PrivateKeyInfo) -> Result<bool, CertFileError> {
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|e| CertFileError::FileReadError {
            path: "<certificate>".to_string(),
            message: format!("Failed to parse certificate: {:?}", e),
        })?;

    // Extract the raw SPKI bytes from the certificate
    let cert_spki = cert.public_key().raw;

    Ok(cert_spki == key_info.public_key_spki.as_slice())
}
