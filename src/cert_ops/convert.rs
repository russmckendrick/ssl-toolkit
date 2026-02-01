//! Certificate format conversion
//!
//! Converts between PEM, DER, and PKCS#12 formats.

use crate::cert_ops::reader::DetectedFormat;
use crate::utils::CertFileError;
use std::path::{Path, PathBuf};
use x509_parser::prelude::*;

/// Convert a PEM certificate file to DER format
pub fn pem_to_der(input: &Path, output: &Path) -> Result<(), CertFileError> {
    let data = std::fs::read(input).map_err(|e| CertFileError::FileReadError {
        path: input.display().to_string(),
        message: e.to_string(),
    })?;

    let pems = ::pem::parse_many(&data).map_err(|e| CertFileError::ConversionError {
        message: format!("Failed to parse PEM: {}", e),
    })?;

    let cert_pem = pems
        .into_iter()
        .find(|p| p.tag() == "CERTIFICATE")
        .ok_or_else(|| CertFileError::ConversionError {
            message: "No CERTIFICATE block found in PEM file".to_string(),
        })?;

    std::fs::write(output, cert_pem.into_contents()).map_err(|e| {
        CertFileError::ConversionError {
            message: format!("Failed to write DER file: {}", e),
        }
    })?;

    Ok(())
}

/// Convert a DER certificate file to PEM format
pub fn der_to_pem(input: &Path, output: &Path) -> Result<(), CertFileError> {
    let data = std::fs::read(input).map_err(|e| CertFileError::FileReadError {
        path: input.display().to_string(),
        message: e.to_string(),
    })?;

    // Validate it's a valid X.509 certificate
    X509Certificate::from_der(&data).map_err(|e| CertFileError::ConversionError {
        message: format!("Input is not a valid DER certificate: {:?}", e),
    })?;

    let pem_block = ::pem::Pem::new("CERTIFICATE", data);
    let pem_str = ::pem::encode(&pem_block);

    std::fs::write(output, pem_str).map_err(|e| CertFileError::ConversionError {
        message: format!("Failed to write PEM file: {}", e),
    })?;

    Ok(())
}

/// Convert PEM certificate and key to PKCS#12 format
pub fn pem_to_p12(
    cert_path: &Path,
    key_path: &Path,
    output: &Path,
    password: Option<&str>,
) -> Result<(), CertFileError> {
    let pwd = password.unwrap_or("");

    // Read certificate(s)
    let cert_data = std::fs::read(cert_path).map_err(|e| CertFileError::FileReadError {
        path: cert_path.display().to_string(),
        message: e.to_string(),
    })?;

    let cert_pems = ::pem::parse_many(&cert_data).map_err(|e| CertFileError::ConversionError {
        message: format!("Failed to parse certificate PEM: {}", e),
    })?;

    let cert_ders: Vec<Vec<u8>> = cert_pems
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| p.into_contents())
        .collect();

    if cert_ders.is_empty() {
        return Err(CertFileError::ConversionError {
            message: "No CERTIFICATE blocks found in cert file".to_string(),
        });
    }

    // Read private key
    let key_data = std::fs::read(key_path).map_err(|e| CertFileError::FileReadError {
        path: key_path.display().to_string(),
        message: e.to_string(),
    })?;

    let key_pems = ::pem::parse_many(&key_data).map_err(|e| CertFileError::ConversionError {
        message: format!("Failed to parse key PEM: {}", e),
    })?;

    let key_pem = key_pems
        .into_iter()
        .find(|p| {
            p.tag() == "PRIVATE KEY" || p.tag() == "RSA PRIVATE KEY" || p.tag() == "EC PRIVATE KEY"
        })
        .ok_or_else(|| CertFileError::ConversionError {
            message: "No private key block found in key file".to_string(),
        })?;

    // Build PKCS#12 using p12-keystore
    let mut keystore = p12_keystore::KeyStore::new();

    // Create certificate objects
    let certs: Result<Vec<p12_keystore::Certificate>, _> = cert_ders
        .iter()
        .map(|der| p12_keystore::Certificate::from_der(der))
        .collect();

    let certs = certs.map_err(|e| CertFileError::Pkcs12Error {
        message: format!("Failed to parse certificate for PKCS#12: {}", e),
    })?;

    // Generate a simple local key ID (SHA-1 of leaf cert)
    let local_key_id = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&cert_ders[0]);
        hasher.finalize().to_vec()
    };

    // Create private key chain entry
    let chain = p12_keystore::PrivateKeyChain::new(key_pem.into_contents(), &local_key_id, certs);

    keystore.add_entry("cert", p12_keystore::KeyStoreEntry::PrivateKeyChain(chain));

    let p12_data = keystore
        .writer(pwd)
        .write()
        .map_err(|e| CertFileError::Pkcs12Error {
            message: format!("Failed to serialize PKCS#12: {}", e),
        })?;

    std::fs::write(output, p12_data).map_err(|e| CertFileError::ConversionError {
        message: format!("Failed to write PKCS#12 file: {}", e),
    })?;

    Ok(())
}

/// Convert PKCS#12 to PEM format (outputs cert + key if available)
pub fn p12_to_pem(
    input: &Path,
    output: &Path,
    password: Option<&str>,
) -> Result<(), CertFileError> {
    let data = std::fs::read(input).map_err(|e| CertFileError::FileReadError {
        path: input.display().to_string(),
        message: e.to_string(),
    })?;

    let pwd = password.unwrap_or("");
    let keystore = p12_keystore::KeyStore::from_pkcs12(&data, pwd).map_err(|e| {
        CertFileError::Pkcs12Error {
            message: format!("Failed to parse PKCS#12: {}", e),
        }
    })?;

    let mut pem_output = String::new();

    for (_alias, entry) in keystore.entries() {
        match entry {
            p12_keystore::KeyStoreEntry::PrivateKeyChain(chain) => {
                // Write private key
                let key_block = ::pem::Pem::new("PRIVATE KEY", chain.key().to_vec());
                pem_output.push_str(&::pem::encode(&key_block));

                // Write certificates
                for cert in chain.chain() {
                    let cert_block = ::pem::Pem::new("CERTIFICATE", cert.as_der().to_vec());
                    pem_output.push_str(&::pem::encode(&cert_block));
                }
            }
            p12_keystore::KeyStoreEntry::Certificate(cert) => {
                let cert_block = ::pem::Pem::new("CERTIFICATE", cert.as_der().to_vec());
                pem_output.push_str(&::pem::encode(&cert_block));
            }
        }
    }

    if pem_output.is_empty() {
        return Err(CertFileError::Pkcs12Error {
            message: "No certificates or keys found in PKCS#12 file".to_string(),
        });
    }

    std::fs::write(output, pem_output).map_err(|e| CertFileError::ConversionError {
        message: format!("Failed to write PEM file: {}", e),
    })?;

    Ok(())
}

/// Generate a default output path by changing the extension
pub fn default_output_path(input: &Path, target_format: &DetectedFormat) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default();
    let ext = match target_format {
        DetectedFormat::Pem => "pem",
        DetectedFormat::Der => "der",
        DetectedFormat::Pkcs12 => "p12",
    };
    input.with_file_name(format!("{}.{}", stem.to_string_lossy(), ext))
}
