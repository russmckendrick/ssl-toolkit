//! PEM export functionality
//!
//! Exports certificate chains in PEM format.

use crate::models::CertificateInfo;
use base64::Engine;

/// PEM exporter for certificates
pub struct PemExporter;

impl PemExporter {
    /// Export a single certificate to PEM format
    pub fn export_certificate(cert: &CertificateInfo) -> String {
        cert.to_pem()
    }

    /// Export a certificate chain to PEM format (includes all certs)
    pub fn export_chain(chain: &[Vec<u8>]) -> String {
        Self::export_chain_internal(chain, false)
    }

    /// Export the intermediate/root chain only (excludes leaf certificate)
    /// This is what users typically need when installing SSL certs
    pub fn export_chain_without_leaf(chain: &[Vec<u8>]) -> String {
        Self::export_chain_internal(chain, true)
    }

    /// Internal function to export chain with optional leaf exclusion
    fn export_chain_internal(chain: &[Vec<u8>], skip_leaf: bool) -> String {
        let mut pem = String::new();
        let start_idx = if skip_leaf { 1 } else { 0 };
        let mut first = true;

        for der in chain.iter().skip(start_idx) {
            if !first {
                pem.push('\n');
            }
            first = false;

            let b64 = base64::engine::general_purpose::STANDARD.encode(der);
            pem.push_str("-----BEGIN CERTIFICATE-----\n");

            for chunk in b64.as_bytes().chunks(64) {
                pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
                pem.push('\n');
            }

            pem.push_str("-----END CERTIFICATE-----\n");
        }

        pem
    }

    /// Export to a base64 data URI
    pub fn to_data_uri(pem: &str) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(pem);
        format!("data:application/x-pem-file;base64,{}", b64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_chain() {
        let chain = vec![
            vec![0x30, 0x82, 0x01, 0x00], // Minimal DER header
        ];

        let pem = PemExporter::export_chain(&chain);
        assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }
}
