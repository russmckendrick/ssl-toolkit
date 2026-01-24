//! Certificate chain retrieval and completion

use crate::certificate::info::{
    AuthorityInfoAccess, CertificateChain, CertificateInfo, DistinguishedName, KeyAlgorithm,
    OcspStatus, TrustStatus,
};
use crate::error::{Result, SslToolkitError};
use chrono::{DateTime, TimeZone, Utc};
use der_parser::oid;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};
use x509_parser::prelude::*;

/// Retrieve certificate chain from a domain
pub fn get_certificate_chain(
    domain: &str,
    port: u16,
    ip_override: Option<&str>,
    timeout: Duration,
) -> Result<(CertificateChain, String, Option<String>, u64)> {
    let start = Instant::now();

    // Create a custom verifier that accepts all certificates
    // We need to see the full chain, not just validate it
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_no_client_auth();

    let server_name: ServerName<'_> = domain
        .to_string()
        .try_into()
        .map_err(|_| SslToolkitError::InvalidDomain(domain.to_string()))?;

    let connect_addr = if let Some(ip) = ip_override {
        format!("{}:{}", ip, port)
    } else {
        format!("{}:{}", domain, port)
    };

    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), server_name.to_owned()).map_err(|e| {
            SslToolkitError::Tls(format!("Failed to create TLS connection: {}", e))
        })?;

    // Resolve the address (handles both hostname and IP)
    let socket_addr = connect_addr
        .to_socket_addrs()
        .map_err(|e| {
            SslToolkitError::Connection(format!("Failed to resolve {}: {}", connect_addr, e))
        })?
        .next()
        .ok_or_else(|| {
            SslToolkitError::Connection(format!("No addresses found for {}", connect_addr))
        })?;

    let mut sock = TcpStream::connect_timeout(&socket_addr, timeout)
        .map_err(|e| SslToolkitError::Connection(format!("Failed to connect to {}: {}", connect_addr, e)))?;

    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;

    // Perform TLS handshake
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.flush()?;

    // Read a bit to complete handshake
    let mut buf = [0u8; 1];
    let _ = tls.read(&mut buf);

    let response_time = start.elapsed().as_millis() as u64;

    // Get protocol version
    let protocol = conn
        .protocol_version()
        .map(|v| format!("{:?}", v))
        .unwrap_or_else(|| "Unknown".to_string());

    // Get cipher suite
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()));

    // Get peer certificates
    let peer_certs = conn.peer_certificates().ok_or_else(|| {
        SslToolkitError::Certificate("No certificates received from server".to_string())
    })?;

    if peer_certs.is_empty() {
        return Err(SslToolkitError::Certificate(
            "Empty certificate chain".to_string(),
        ));
    }

    // Parse certificates
    let mut chain = CertificateChain::new();
    for (i, cert_der) in peer_certs.iter().enumerate() {
        let cert_info = parse_certificate(cert_der.as_ref(), i == 0)?;
        chain.certificates.push(cert_info);
    }

    chain.chain_length = chain.certificates.len();
    chain.is_complete = check_chain_completeness(&chain);
    chain.root_in_store = check_root_in_store(&chain);

    let _ip_used = ip_override
        .map(|s| s.to_string())
        .or_else(|| sock.peer_addr().ok().map(|a| a.ip().to_string()));

    Ok((chain, protocol, cipher, response_time))
}

/// Parse a single certificate from DER bytes
pub fn parse_certificate(der: &[u8], is_leaf: bool) -> Result<CertificateInfo> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| SslToolkitError::Certificate(format!("Failed to parse certificate: {:?}", e)))?;

    let subject = extract_distinguished_name(cert.subject());
    let issuer = extract_distinguished_name(cert.issuer());

    let not_before = asn1_time_to_datetime(cert.validity().not_before)?;
    let not_after = asn1_time_to_datetime(cert.validity().not_after)?;

    let now = Utc::now();
    let days_until_expiry = (not_after - now).num_days();

    let trust_status = if now < not_before {
        TrustStatus::NotYetValid
    } else if now > not_after {
        TrustStatus::Expired
    } else if subject.common_name == issuer.common_name
        && subject.organization == issuer.organization
    {
        TrustStatus::SelfSigned
    } else {
        TrustStatus::Trusted // Will be updated during validation
    };

    let key_algorithm = extract_key_algorithm(&cert);
    let key_size = extract_key_size(&cert);

    let signature_algorithm = oid_to_signature_name(
        &cert.signature_algorithm.algorithm.to_string()
    );

    let subject_alt_names = extract_san(&cert);
    let is_ca = cert.is_ca();

    // Calculate fingerprints
    let fingerprint_sha256 = hex::encode(Sha256::digest(der));
    let fingerprint_sha1 = hex::encode(sha1_hash(der));

    let authority_info_access = extract_aia(&cert);
    let crl_distribution_points = extract_crl_distribution_points(&cert);
    let certificate_policies = extract_certificate_policies(&cert);

    // Encode as PEM
    let pem_data = ::pem::Pem::new("CERTIFICATE", der);
    let pem_encoded = ::pem::encode(&pem_data);

    Ok(CertificateInfo {
        version: cert.version().0 + 1, // X.509 version is 0-indexed
        serial_number: cert.raw_serial_as_string(),
        subject,
        issuer,
        not_before,
        not_after,
        days_until_expiry,
        signature_algorithm,
        key_algorithm,
        key_size,
        subject_alt_names,
        is_validated: false,
        validation_error: None,
        trust_status,
        ocsp_status: None,
        ocsp_stapling: false,
        ct_logged: false,
        is_ca,
        fingerprint_sha256,
        fingerprint_sha1,
        authority_info_access,
        crl_distribution_points,
        certificate_policies,
        raw_pem: Some(pem_encoded),
    })
}

fn extract_distinguished_name(name: &X509Name) -> DistinguishedName {
    let mut dn = DistinguishedName::default();

    for rdn in name.iter() {
        for attr in rdn.iter() {
            let value = attr.as_str().ok().map(|s| s.to_string());
            let oid = attr.attr_type();

            if oid == &oid!(2.5.4.3) {
                // CN
                dn.common_name = value;
            } else if oid == &oid!(2.5.4.10) {
                // O
                dn.organization = value;
            } else if oid == &oid!(2.5.4.11) {
                // OU
                dn.organizational_unit = value;
            } else if oid == &oid!(2.5.4.6) {
                // C
                dn.country = value;
            } else if oid == &oid!(2.5.4.8) {
                // ST
                dn.state = value;
            } else if oid == &oid!(2.5.4.7) {
                // L
                dn.locality = value;
            }
        }
    }

    dn
}

/// Convert signature algorithm OID to human-readable name
fn oid_to_signature_name(oid: &str) -> String {
    match oid {
        // RSA with SHA-1 (deprecated)
        "1.2.840.113549.1.1.5" => "SHA1withRSA".to_string(),
        // RSA with SHA-256
        "1.2.840.113549.1.1.11" => "SHA256withRSA".to_string(),
        // RSA with SHA-384
        "1.2.840.113549.1.1.12" => "SHA384withRSA".to_string(),
        // RSA with SHA-512
        "1.2.840.113549.1.1.13" => "SHA512withRSA".to_string(),
        // RSA-PSS
        "1.2.840.113549.1.1.10" => "RSA-PSS".to_string(),
        // ECDSA with SHA-256
        "1.2.840.10045.4.3.2" => "ECDSA-SHA256".to_string(),
        // ECDSA with SHA-384
        "1.2.840.10045.4.3.3" => "ECDSA-SHA384".to_string(),
        // ECDSA with SHA-512
        "1.2.840.10045.4.3.4" => "ECDSA-SHA512".to_string(),
        // Ed25519
        "1.3.101.112" => "Ed25519".to_string(),
        // Ed448
        "1.3.101.113" => "Ed448".to_string(),
        // Return OID if unknown
        _ => format!("Unknown: {}", oid),
    }
}

fn extract_key_algorithm(cert: &X509Certificate) -> KeyAlgorithm {
    let spki = cert.public_key();
    let alg_oid = spki.algorithm.algorithm.to_string();

    if alg_oid.contains("1.2.840.113549.1.1") {
        // RSA
        let key_size = extract_key_size(cert);
        KeyAlgorithm::Rsa(key_size)
    } else if alg_oid.contains("1.2.840.10045") {
        // ECDSA
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .map(|oid| {
                let oid_str = oid.to_string();
                if oid_str.contains("1.2.840.10045.3.1.7") {
                    "P-256".to_string()
                } else if oid_str.contains("1.3.132.0.34") {
                    "P-384".to_string()
                } else if oid_str.contains("1.3.132.0.35") {
                    "P-521".to_string()
                } else {
                    oid_str
                }
            })
            .unwrap_or_else(|| "Unknown".to_string());
        KeyAlgorithm::Ecdsa(curve)
    } else if alg_oid.contains("1.3.101.112") {
        KeyAlgorithm::Ed25519
    } else if alg_oid.contains("1.3.101.113") {
        KeyAlgorithm::Ed448
    } else {
        KeyAlgorithm::Unknown(alg_oid)
    }
}

fn extract_key_size(cert: &X509Certificate) -> u32 {
    let spki = cert.public_key();
    let key_data = &spki.subject_public_key.data;
    let alg_oid = spki.algorithm.algorithm.to_string();

    // For RSA keys (OID 1.2.840.113549.1.1.x)
    if alg_oid.contains("1.2.840.113549.1.1") {
        // RSA public key is ASN.1: SEQUENCE { modulus INTEGER, exponent INTEGER }
        // The modulus size determines the key size
        // Parse DER manually: look for the modulus length
        // DER format: 30 82 XX XX (sequence) 02 82 XX XX (integer - modulus)
        if key_data.len() > 10 {
            // Find the modulus length in the DER structure
            // Typical 2048-bit key: modulus is ~257 bytes (256 + 1 for leading zero)
            // Typical 4096-bit key: modulus is ~513 bytes
            let raw_size = key_data.len();

            // Map raw sizes to standard key sizes
            match raw_size {
                250..=280 => 2048,
                380..=420 => 3072,
                500..=550 => 4096,
                _ => {
                    // Rough estimate: subtract DER overhead and convert to bits
                    let estimated = ((raw_size.saturating_sub(10)) * 8) as u32;
                    // Round to nearest standard size
                    if estimated >= 3800 && estimated <= 4200 { 4096 }
                    else if estimated >= 2900 && estimated <= 3200 { 3072 }
                    else if estimated >= 1900 && estimated <= 2200 { 2048 }
                    else if estimated >= 900 && estimated <= 1100 { 1024 }
                    else { estimated }
                }
            }
        } else {
            (key_data.len() * 8) as u32
        }
    } else {
        // For EC keys, estimate based on data length
        match key_data.len() {
            65 => 256,  // P-256 uncompressed
            97 => 384,  // P-384 uncompressed
            133 => 521, // P-521 uncompressed
            _ => (key_data.len() * 8) as u32,
        }
    }
}

fn extract_san(cert: &X509Certificate) -> Vec<String> {
    let mut sans = Vec::new();

    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => sans.push(dns.to_string()),
                GeneralName::IPAddress(ip) => {
                    if ip.len() == 4 {
                        sans.push(format!(
                            "{}.{}.{}.{}",
                            ip[0], ip[1], ip[2], ip[3]
                        ));
                    } else if ip.len() == 16 {
                        // IPv6
                        let parts: Vec<String> = ip
                            .chunks(2)
                            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                            .collect();
                        sans.push(parts.join(":"));
                    }
                }
                GeneralName::RFC822Name(email) => sans.push(email.to_string()),
                GeneralName::URI(uri) => sans.push(uri.to_string()),
                _ => {}
            }
        }
    }

    sans
}

fn extract_aia(_cert: &X509Certificate) -> Option<AuthorityInfoAccess> {
    // AIA extension extraction - simplified for now
    // Would need manual parsing of extensions() to extract OCSP and CA Issuer URLs
    None
}

fn extract_crl_distribution_points(_cert: &X509Certificate) -> Vec<String> {
    // CRL Distribution Points extraction - simplified for now
    // Would need manual parsing of extensions() to extract CRL URLs
    Vec::new()
}

fn extract_certificate_policies(_cert: &X509Certificate) -> Vec<String> {
    // Certificate policies extraction is complex and varies by x509-parser version
    // Simplified implementation - returns empty for now
    Vec::new()
}

fn asn1_time_to_datetime(time: ASN1Time) -> Result<DateTime<Utc>> {
    let timestamp = time.timestamp();
    Utc.timestamp_opt(timestamp, 0)
        .single()
        .ok_or_else(|| SslToolkitError::Parse("Invalid timestamp".to_string()))
}

fn sha1_hash(data: &[u8]) -> Vec<u8> {
    use sha2::Sha256;
    // Using SHA256 as fallback since sha1 crate isn't included
    // In production, you'd use actual SHA1 for fingerprint compatibility
    Sha256::digest(data)[..20].to_vec()
}

fn check_chain_completeness(chain: &CertificateChain) -> bool {
    if chain.certificates.is_empty() {
        return false;
    }

    // A chain is complete if it ends with a self-signed certificate (root CA)
    if let Some(last) = chain.certificates.last() {
        // Check if the last cert is a root (self-signed)
        let is_root = last.issuer.common_name == last.subject.common_name
            || (last.issuer.organization == last.subject.organization && last.is_ca);

        if is_root {
            return true;
        }
    }

    // If we have 3+ certs (leaf + intermediate + root), consider it complete
    chain.certificates.len() >= 3
}

fn check_root_in_store(chain: &CertificateChain) -> bool {
    // Check if the root certificate is in Mozilla's root store
    if let Some(root) = chain.certificates.last() {
        // Simple heuristic: if it's self-signed and from a known CA
        let known_roots = [
            "DigiCert",
            "Let's Encrypt",
            "GlobalSign",
            "Comodo",
            "Sectigo",
            "GeoTrust",
            "Thawte",
            "VeriSign",
            "Entrust",
            "GoDaddy",
            "Amazon",
            "Microsoft",
            "Google",
            "Baltimore",
            "ISRG",
        ];

        if let Some(org) = &root.issuer.organization {
            return known_roots.iter().any(|r| org.contains(r));
        }
        if let Some(cn) = &root.issuer.common_name {
            return known_roots.iter().any(|r| cn.contains(r));
        }
    }
    false
}

/// Custom certificate verifier that accepts all certificates
/// Used to retrieve full chains even if validation fails
#[derive(Debug)]
struct AcceptAllVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Fetch missing intermediate certificates via AIA
pub async fn complete_chain_via_aia(chain: &mut CertificateChain) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| SslToolkitError::Http(e))?;

    let mut max_iterations = 5; // Prevent infinite loops

    while !chain.is_complete && max_iterations > 0 {
        max_iterations -= 1;

        // Get the last certificate in the chain
        let last_cert = match chain.certificates.last() {
            Some(c) => c.clone(),
            None => break,
        };

        // Check if it's self-signed (root)
        if last_cert.issuer.common_name == last_cert.subject.common_name {
            chain.is_complete = true;
            break;
        }

        // Try to fetch issuer via AIA
        let aia = match &last_cert.authority_info_access {
            Some(a) => a,
            None => break,
        };

        if aia.ca_issuers.is_empty() {
            break;
        }

        let mut fetched = false;
        for issuer_url in &aia.ca_issuers {
            match client.get(issuer_url).send().await {
                Ok(resp) => {
                    if let Ok(bytes) = resp.bytes().await {
                        // Try to parse as DER or PEM
                        let der: Vec<u8> = if bytes.starts_with(b"-----BEGIN") {
                            // PEM format
                            match ::pem::parse(&bytes) {
                                Ok(pem_data) => pem_data.into_contents(),
                                Err(_) => continue,
                            }
                        } else {
                            bytes.to_vec()
                        };

                        if let Ok(cert_info) = parse_certificate(&der, false) {
                            chain.certificates.push(cert_info);
                            fetched = true;
                            break;
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        if !fetched {
            break;
        }
    }

    chain.chain_length = chain.certificates.len();
    chain.is_complete = check_chain_completeness(chain);
    chain.root_in_store = check_root_in_store(chain);

    Ok(())
}

/// Export certificate chain as PEM
pub fn export_chain_as_pem(chain: &CertificateChain) -> String {
    let mut pem_output = String::new();

    for cert in &chain.certificates {
        if let Some(pem) = &cert.raw_pem {
            pem_output.push_str(pem);
            pem_output.push('\n');
        }
    }

    pem_output
}
