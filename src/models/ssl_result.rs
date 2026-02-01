//! SSL/TLS analysis result types

use serde::Serialize;
use std::fmt;
use std::net::IpAddr;

/// TLS protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum TlsProtocol {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl fmt::Display for TlsProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsProtocol::Ssl30 => write!(f, "SSLv3"),
            TlsProtocol::Tls10 => write!(f, "TLS 1.0"),
            TlsProtocol::Tls11 => write!(f, "TLS 1.1"),
            TlsProtocol::Tls12 => write!(f, "TLS 1.2"),
            TlsProtocol::Tls13 => write!(f, "TLS 1.3"),
        }
    }
}

impl TlsProtocol {
    /// Check if this protocol is considered secure
    pub fn is_secure(&self) -> bool {
        matches!(self, TlsProtocol::Tls12 | TlsProtocol::Tls13)
    }

    /// Check if this protocol is deprecated
    pub fn is_deprecated(&self) -> bool {
        matches!(
            self,
            TlsProtocol::Ssl30 | TlsProtocol::Tls10 | TlsProtocol::Tls11
        )
    }
}

/// Protocol support status
#[derive(Debug, Clone, Serialize)]
pub struct ProtocolSupport {
    pub protocol: TlsProtocol,
    pub supported: bool,
    pub preferred: bool,
}

/// Cipher suite information
#[derive(Debug, Clone, Serialize)]
pub struct CipherSuite {
    /// Cipher suite name (e.g., TLS_AES_256_GCM_SHA384)
    pub name: String,
    /// Key exchange algorithm
    pub key_exchange: String,
    /// Authentication algorithm
    pub authentication: String,
    /// Encryption algorithm
    pub encryption: String,
    /// MAC algorithm
    pub mac: String,
    /// Key size in bits
    pub key_size: u32,
    /// Whether this cipher is considered secure
    pub is_secure: bool,
    /// Whether this cipher has known weaknesses
    pub has_weakness: bool,
}

impl CipherSuite {
    /// Create a cipher suite from a name
    pub fn from_name(name: &str) -> Self {
        // Parse common cipher suite patterns
        let is_secure = !name.contains("NULL")
            && !name.contains("EXPORT")
            && !name.contains("DES")
            && !name.contains("RC4")
            && !name.contains("MD5");

        let has_weakness = name.contains("CBC") || name.contains("SHA1") || name.contains("RSA");

        Self {
            name: name.to_string(),
            key_exchange: Self::extract_key_exchange(name),
            authentication: Self::extract_auth(name),
            encryption: Self::extract_encryption(name),
            mac: Self::extract_mac(name),
            key_size: Self::extract_key_size(name),
            is_secure,
            has_weakness,
        }
    }

    fn extract_key_exchange(name: &str) -> String {
        if name.contains("ECDHE") {
            "ECDHE".to_string()
        } else if name.contains("DHE") {
            "DHE".to_string()
        } else if name.contains("ECDH") {
            "ECDH".to_string()
        } else if name.contains("DH") {
            "DH".to_string()
        } else if name.contains("RSA") {
            "RSA".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn extract_auth(name: &str) -> String {
        if name.contains("ECDSA") {
            "ECDSA".to_string()
        } else if name.contains("RSA") {
            "RSA".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn extract_encryption(name: &str) -> String {
        if name.contains("AES_256_GCM") {
            "AES-256-GCM".to_string()
        } else if name.contains("AES_128_GCM") {
            "AES-128-GCM".to_string()
        } else if name.contains("CHACHA20") {
            "ChaCha20-Poly1305".to_string()
        } else if name.contains("AES256") || name.contains("AES_256") {
            "AES-256".to_string()
        } else if name.contains("AES128") || name.contains("AES_128") {
            "AES-128".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn extract_mac(name: &str) -> String {
        if name.contains("SHA384") {
            "SHA-384".to_string()
        } else if name.contains("SHA256") {
            "SHA-256".to_string()
        } else if name.contains("SHA1") || name.contains("SHA") && !name.contains("SHA2") {
            "SHA-1".to_string()
        } else if name.contains("GCM") || name.contains("CHACHA20") {
            "AEAD".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn extract_key_size(name: &str) -> u32 {
        if name.contains("256") {
            256
        } else if name.contains("128") {
            128
        } else {
            0
        }
    }
}

/// Complete SSL/TLS analysis results
#[derive(Debug, Clone, Serialize)]
pub struct SslInfo {
    /// Target IP address
    pub ip: IpAddr,
    /// Target port
    pub port: u16,
    /// Negotiated protocol
    pub protocol: TlsProtocol,
    /// Negotiated cipher suite
    pub cipher_suite: String,
    /// List of supported protocols
    pub supported_protocols: Vec<ProtocolSupport>,
    /// List of supported cipher suites
    pub cipher_suites: Vec<CipherSuite>,
    /// Certificate chain (DER encoded)
    pub certificate_chain: Vec<Vec<u8>>,
    /// Whether the server supports secure renegotiation
    pub secure_renegotiation: bool,
    /// Whether OCSP stapling is supported
    pub ocsp_stapling: bool,
    /// Whether the certificate chain was verified by a trusted CA
    /// (false if permissive/fallback verification was used)
    pub trust_verified: bool,
}
