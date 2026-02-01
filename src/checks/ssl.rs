//! SSL/TLS checker
//!
//! Performs SSL/TLS handshake and analyzes protocol and cipher support.
//! Falls back to permissive certificate verification when strict verification
//! fails, allowing analysis of self-signed and otherwise untrusted certificates.

use crate::config::settings::SslSettings;
use crate::models::{CipherSuite, ProtocolSupport, SslInfo, TlsProtocol};
use crate::utils::SslError;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;

/// A certificate verifier that accepts any certificate.
/// Used as a fallback to allow analysis of self-signed/untrusted certs.
#[derive(Debug)]
struct AcceptAnyCertVerifier;

impl ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// A verifier wrapper that captures the OCSP response bytes from the TLS handshake
/// before delegating to an inner verifier.
#[derive(Debug)]
struct OcspCapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    ocsp_response: Arc<Mutex<Vec<u8>>>,
}

impl OcspCapturingVerifier {
    fn new(inner: Arc<dyn ServerCertVerifier>, ocsp_response: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            inner,
            ocsp_response,
        }
    }
}

impl ServerCertVerifier for OcspCapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if !ocsp_response.is_empty() {
            if let Ok(mut stored) = self.ocsp_response.lock() {
                *stored = ocsp_response.to_vec();
            }
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// SSL/TLS checker
pub struct SslChecker {
    settings: SslSettings,
}

impl SslChecker {
    /// Create a new SSL checker with the given settings
    pub fn new(settings: SslSettings) -> Self {
        // Ensure a default crypto provider is installed (needed when multiple
        // providers are available, e.g. when reqwest enables both ring and aws-lc-rs)
        let _ = rustls::crypto::ring::default_provider().install_default();
        Self { settings }
    }

    /// Perform an SSL/TLS check on the given target.
    /// First tries strict certificate verification, then falls back to
    /// permissive mode if the cert is untrusted (self-signed, unknown CA, etc.).
    pub async fn check(&self, domain: &str, ip: IpAddr, port: u16) -> Result<SslInfo, SslError> {
        // Try strict verification first
        match self.check_with_config(domain, ip, port, false).await {
            Ok(mut info) => {
                info.trust_verified = true;
                Ok(info)
            }
            Err(e) => {
                let err_msg = format!("{}", e);
                let is_cert_error = err_msg.contains("certificate")
                    || err_msg.contains("CaUsedAsEndEntity")
                    || err_msg.contains("UnknownIssuer")
                    || err_msg.contains("SelfSigned")
                    || err_msg.contains("InvalidPurpose")
                    || err_msg.contains("invalid peer");

                if is_cert_error {
                    // Retry with permissive verification to allow cert analysis
                    let mut info = self.check_with_config(domain, ip, port, true).await?;
                    info.trust_verified = false;
                    Ok(info)
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn check_with_config(
        &self,
        domain: &str,
        ip: IpAddr,
        port: u16,
        accept_invalid_certs: bool,
    ) -> Result<SslInfo, SslError> {
        let ocsp_captured = Arc::new(Mutex::new(Vec::new()));

        // Build a temporary config to get the default crypto provider,
        // then rebuild with our OCSP-capturing verifier wrapper
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = if accept_invalid_certs {
            let inner: Arc<dyn ServerCertVerifier> = Arc::new(AcceptAnyCertVerifier);
            let verifier = OcspCapturingVerifier::new(inner, Arc::clone(&ocsp_captured));
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        } else {
            // First build a normal config to establish crypto provider
            let normal_config = ClientConfig::builder()
                .with_root_certificates(root_store.clone())
                .with_no_client_auth();

            // Get the verifier from the normal config's internal state
            // We need to rebuild with our wrapper, so use the provider from the normal config
            let provider = normal_config.crypto_provider().clone();

            let inner: Arc<dyn ServerCertVerifier> =
                rustls::client::WebPkiServerVerifier::builder_with_provider(
                    Arc::new(root_store),
                    provider,
                )
                .build()
                .map_err(|e| SslError::ConfigurationError {
                    message: format!("Failed to build verifier: {}", e),
                })?;
            let verifier = OcspCapturingVerifier::new(inner, Arc::clone(&ocsp_captured));
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        };

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        // Connect TCP
        let addr = std::net::SocketAddr::new(ip, port);
        let stream =
            tokio::time::timeout(self.settings.connect_timeout(), TcpStream::connect(addr))
                .await
                .map_err(|_| SslError::ConnectionError {
                    message: "TCP connection timed out".to_string(),
                })?
                .map_err(|e| SslError::ConnectionError {
                    message: e.to_string(),
                })?;

        // Perform TLS handshake
        let server_name =
            ServerName::try_from(domain.to_string()).map_err(|_| SslError::ConfigurationError {
                message: format!("Invalid server name: {}", domain),
            })?;

        let tls_stream = tokio::time::timeout(
            self.settings.handshake_timeout(),
            connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| SslError::HandshakeFailed {
            message: "TLS handshake timed out".to_string(),
        })?
        .map_err(|e| SslError::HandshakeFailed {
            message: e.to_string(),
        })?;

        // Extract connection info
        let (_, client_connection) = tls_stream.get_ref();

        let protocol = match client_connection.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_3) => TlsProtocol::Tls13,
            Some(rustls::ProtocolVersion::TLSv1_2) => TlsProtocol::Tls12,
            _ => TlsProtocol::Tls12,
        };

        let cipher_suite = client_connection
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()))
            .unwrap_or_else(|| "Unknown".to_string());

        // Get certificate chain
        let certificate_chain: Vec<Vec<u8>> = client_connection
            .peer_certificates()
            .map(|certs| certs.iter().map(|c| c.as_ref().to_vec()).collect())
            .unwrap_or_default();

        // Check for legacy protocol support if enabled
        let mut supported_protocols = vec![
            ProtocolSupport {
                protocol: TlsProtocol::Tls13,
                supported: protocol == TlsProtocol::Tls13,
                preferred: protocol == TlsProtocol::Tls13,
            },
            ProtocolSupport {
                protocol: TlsProtocol::Tls12,
                supported: true,
                preferred: protocol == TlsProtocol::Tls12,
            },
        ];

        if self.settings.check_legacy_protocols {
            let tls10_supported = self
                .check_legacy_protocol(ip, port, domain, "TLSv1.0")
                .await;
            let tls11_supported = self
                .check_legacy_protocol(ip, port, domain, "TLSv1.1")
                .await;

            supported_protocols.push(ProtocolSupport {
                protocol: TlsProtocol::Tls11,
                supported: tls11_supported,
                preferred: false,
            });
            supported_protocols.push(ProtocolSupport {
                protocol: TlsProtocol::Tls10,
                supported: tls10_supported,
                preferred: false,
            });
        }

        let cipher_suites = vec![CipherSuite::from_name(&cipher_suite)];

        let ocsp_response = ocsp_captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let has_ocsp_stapling = !ocsp_response.is_empty();

        Ok(SslInfo {
            ip,
            port,
            protocol,
            cipher_suite,
            supported_protocols,
            cipher_suites,
            certificate_chain,
            secure_renegotiation: true,
            ocsp_stapling: has_ocsp_stapling,
            ocsp_response,
            trust_verified: false, // Set by caller in check()
        })
    }

    /// Check if a legacy protocol is supported using native-tls
    async fn check_legacy_protocol(
        &self,
        ip: IpAddr,
        port: u16,
        domain: &str,
        protocol: &str,
    ) -> bool {
        use native_tls::TlsConnector;

        let min_protocol = match protocol {
            "TLSv1.0" => native_tls::Protocol::Tlsv10,
            "TLSv1.1" => native_tls::Protocol::Tlsv11,
            _ => return false,
        };

        let max_protocol = min_protocol;

        let connector = match TlsConnector::builder()
            .min_protocol_version(Some(min_protocol))
            .max_protocol_version(Some(max_protocol))
            .danger_accept_invalid_certs(true)
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        let connector = tokio_native_tls::TlsConnector::from(connector);

        let addr = std::net::SocketAddr::new(ip, port);

        let stream =
            match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
                Ok(Ok(s)) => s,
                _ => return false,
            };

        tokio::time::timeout(Duration::from_secs(3), connector.connect(domain, stream))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ssl_check_google() {
        let settings = SslSettings::default();
        let checker = SslChecker::new(settings);

        let result = checker
            .check("google.com", "142.250.80.46".parse().unwrap(), 443)
            .await;

        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.protocol.is_secure());
        assert!(!info.certificate_chain.is_empty());
    }
}
