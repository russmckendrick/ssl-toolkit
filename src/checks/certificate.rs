//! Certificate parsing and validation
//!
//! Analyzes X.509 certificates using x509-parser.

use crate::models::{CertificateInfo, CertificateSummary, CertificateType};
use crate::utils::CertificateError;
use chrono::{DateTime, TimeZone, Utc};
use sha2::Digest;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

/// Certificate checker and parser
pub struct CertificateChecker;

impl CertificateChecker {
    /// Create a new certificate checker
    pub fn new() -> Self {
        Self
    }

    /// Analyze a certificate chain (DER encoded certificates)
    pub fn analyze(&self, chain: &[Vec<u8>]) -> Result<CertificateInfo, CertificateError> {
        if chain.is_empty() {
            return Err(CertificateError::ParseError {
                message: "Empty certificate chain".to_string(),
            });
        }

        // Parse the leaf certificate (first in chain)
        self.parse_certificate(&chain[0])
    }

    /// Parse a single DER-encoded certificate
    pub fn parse_certificate(&self, der: &[u8]) -> Result<CertificateInfo, CertificateError> {
        let (_, cert) =
            X509Certificate::from_der(der).map_err(|e| CertificateError::ParseError {
                message: format!("Failed to parse certificate: {:?}", e),
            })?;

        // Extract subject
        let subject = cert.subject().to_string();

        // Extract issuer
        let issuer = cert.issuer().to_string();

        // Extract serial number
        let serial = cert
            .serial
            .to_bytes_be()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":");

        // Calculate thumbprint (SHA-256)
        let mut hasher = sha2::Sha256::new();
        hasher.update(der);
        let thumbprint = hasher
            .finalize()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":");

        // Extract validity dates
        let not_before = asn1_time_to_datetime(cert.validity().not_before)?;
        let not_after = asn1_time_to_datetime(cert.validity().not_after)?;

        // Extract SANs
        let san = self.extract_san(&cert);

        // Extract public key info
        let (public_key_algorithm, public_key_size) = self.extract_public_key_info(&cert);

        // Extract signature algorithm
        let signature_algorithm = cert.signature_algorithm.algorithm.to_string();

        // Check if self-signed
        let is_self_signed = cert.subject() == cert.issuer();

        // Check if CA
        let is_ca = cert
            .basic_constraints()
            .map(|bc| bc.map(|ext| ext.value.ca).unwrap_or(false))
            .unwrap_or(false);

        // Extract key usage
        let key_usage = self.extract_key_usage(&cert);

        // Extract extended key usage
        let extended_key_usage = self.extract_extended_key_usage(&cert);

        // Extract OCSP responder URL and CRL distribution points
        let ocsp_responder_url = self.extract_ocsp_responder_url(&cert);
        let crl_distribution_points = self.extract_crl_distribution_points(&cert);

        Ok(CertificateInfo {
            subject,
            issuer,
            serial,
            thumbprint,
            not_before,
            not_after,
            san,
            public_key_algorithm,
            public_key_size,
            signature_algorithm,
            is_self_signed,
            is_ca,
            version: cert.version().0 + 1, // X.509 version is 0-indexed
            key_usage,
            extended_key_usage,
            raw_der: der.to_vec(),
            ocsp_responder_url,
            crl_distribution_points,
            revocation: None,
        })
    }

    /// Parse the entire certificate chain
    pub fn parse_chain(
        &self,
        chain: &[Vec<u8>],
    ) -> Result<Vec<CertificateSummary>, CertificateError> {
        let mut summaries = Vec::new();

        for (index, der) in chain.iter().enumerate() {
            let info = self.parse_certificate(der)?;

            let cert_type = if index == 0 {
                CertificateType::Leaf
            } else if info.is_self_signed {
                CertificateType::Root
            } else {
                CertificateType::Intermediate
            };

            // Extract CN from subject
            let subject_cn = extract_cn(&info.subject);
            let issuer_cn = extract_cn(&info.issuer);

            summaries.push(CertificateSummary {
                cert_type,
                subject_cn,
                issuer_cn,
                valid_from: info.not_before.format("%Y-%m-%d").to_string(),
                valid_until: info.not_after.format("%Y-%m-%d").to_string(),
                days_until_expiry: info.days_until_expiry(),
                is_valid: info.is_time_valid() && !info.is_self_signed,
            });
        }

        Ok(summaries)
    }

    fn extract_san(&self, cert: &X509Certificate) -> Vec<String> {
        let mut sans = Vec::new();

        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                match name {
                    GeneralName::DNSName(dns) => sans.push(dns.to_string()),
                    GeneralName::IPAddress(ip) => {
                        if ip.len() == 4 {
                            sans.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                        } else if ip.len() == 16 {
                            // IPv6
                            let parts: Vec<String> = ip
                                .chunks(2)
                                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                                .collect();
                            sans.push(parts.join(":"));
                        }
                    }
                    _ => {}
                }
            }
        }

        sans
    }

    fn extract_public_key_info(&self, cert: &X509Certificate) -> (String, u32) {
        let pk = cert.public_key();
        let algorithm = pk.algorithm.algorithm.to_string();

        let key_size = match pk.parsed() {
            Ok(PublicKey::RSA(rsa)) => (rsa.key_size() * 8) as u32,
            Ok(PublicKey::EC(ec)) => {
                // EC key size is typically the curve size
                (ec.key_size() * 8) as u32
            }
            _ => 0,
        };

        (algorithm, key_size)
    }

    fn extract_key_usage(&self, cert: &X509Certificate) -> Vec<String> {
        let mut usages = Vec::new();

        if let Ok(Some(ku)) = cert.key_usage() {
            let flags = ku.value;
            if flags.digital_signature() {
                usages.push("Digital Signature".to_string());
            }
            if flags.non_repudiation() {
                usages.push("Non-Repudiation".to_string());
            }
            if flags.key_encipherment() {
                usages.push("Key Encipherment".to_string());
            }
            if flags.data_encipherment() {
                usages.push("Data Encipherment".to_string());
            }
            if flags.key_agreement() {
                usages.push("Key Agreement".to_string());
            }
            if flags.key_cert_sign() {
                usages.push("Certificate Sign".to_string());
            }
            if flags.crl_sign() {
                usages.push("CRL Sign".to_string());
            }
        }

        usages
    }

    /// Extract OCSP responder URL from the Authority Information Access extension
    fn extract_ocsp_responder_url(&self, cert: &X509Certificate) -> Option<String> {
        for ext in cert.extensions() {
            if ext.oid == x509_parser::oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS {
                if let Ok((_, aia)) =
                    x509_parser::extensions::AuthorityInfoAccess::from_der(ext.value)
                {
                    for desc in aia.accessdescs.iter() {
                        // OID 1.3.6.1.5.5.7.48.1 = OCSP
                        if desc.access_method.to_string() == "1.3.6.1.5.5.7.48.1" {
                            if let GeneralName::URI(uri) = desc.access_location {
                                return Some(uri.to_string());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract CRL distribution points from the certificate
    fn extract_crl_distribution_points(&self, cert: &X509Certificate) -> Vec<String> {
        let mut points = Vec::new();
        for ext in cert.extensions() {
            if ext.oid == x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS {
                if let Ok((_, cdp)) =
                    x509_parser::extensions::CRLDistributionPoints::from_der(ext.value)
                {
                    for dp in cdp.iter() {
                        if let Some(x509_parser::extensions::DistributionPointName::FullName(
                            names,
                        )) = &dp.distribution_point
                        {
                            for name in names {
                                if let GeneralName::URI(uri) = name {
                                    points.push(uri.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        points
    }

    fn extract_extended_key_usage(&self, cert: &X509Certificate) -> Vec<String> {
        let mut usages = Vec::new();

        if let Ok(Some(eku)) = cert.extended_key_usage() {
            if eku.value.server_auth {
                usages.push("Server Authentication".to_string());
            }
            if eku.value.client_auth {
                usages.push("Client Authentication".to_string());
            }
            if eku.value.code_signing {
                usages.push("Code Signing".to_string());
            }
            if eku.value.email_protection {
                usages.push("Email Protection".to_string());
            }
            if eku.value.time_stamping {
                usages.push("Time Stamping".to_string());
            }
            if eku.value.ocsp_signing {
                usages.push("OCSP Signing".to_string());
            }
        }

        usages
    }
}

impl Default for CertificateChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert ASN.1 time to chrono DateTime
fn asn1_time_to_datetime(time: ASN1Time) -> Result<DateTime<Utc>, CertificateError> {
    let timestamp = time.timestamp();
    Utc.timestamp_opt(timestamp, 0)
        .single()
        .ok_or_else(|| CertificateError::ParseError {
            message: "Invalid timestamp in certificate".to_string(),
        })
}

/// Extract common name from a distinguished name string
fn extract_cn(dn: &str) -> String {
    // DN format: "CN=example.com, O=Example Inc, ..."
    for part in dn.split(',') {
        let part = part.trim();
        if let Some(cn) = part.strip_prefix("CN=") {
            return cn.to_string();
        }
    }
    dn.to_string()
}

// Tests for certificate checking can be found in tests/integration/
// In practice, testing requires real certificates from badssl.com
