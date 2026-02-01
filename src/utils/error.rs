//! Custom error types for SSL-Toolkit
//!
//! This module defines domain-specific error types using `thiserror` for
//! all the different failure modes that can occur during SSL/TLS diagnostics.

use std::net::IpAddr;
use thiserror::Error;

/// Top-level error type for the SSL-Toolkit application
#[derive(Error, Debug)]
pub enum ToolkitError {
    #[error("DNS resolution error: {0}")]
    Dns(#[from] DnsError),

    #[error("TCP connection error: {0}")]
    Tcp(#[from] TcpError),

    #[error("SSL/TLS error: {0}")]
    Ssl(#[from] SslError),

    #[error("Certificate error: {0}")]
    Certificate(#[from] CertificateError),

    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Report generation error: {0}")]
    Report(#[from] ReportError),

    #[error("WHOIS lookup error: {0}")]
    Whois(#[from] WhoisError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// DNS resolution errors
#[derive(Error, Debug)]
pub enum DnsError {
    #[error("No DNS records found for domain: {domain}")]
    NoRecords { domain: String },

    #[error("DNS query timed out for {domain} using {provider}")]
    Timeout { domain: String, provider: String },

    #[error("Invalid domain name: {domain}")]
    InvalidDomain { domain: String },

    #[error("DNS resolution failed for {domain}: {message}")]
    ResolutionFailed { domain: String, message: String },

    #[error("All DNS providers failed for {domain}")]
    AllProvidersFailed { domain: String },
}

/// TCP connection errors
#[derive(Error, Debug)]
pub enum TcpError {
    #[error("Connection refused to {ip}:{port}")]
    ConnectionRefused { ip: IpAddr, port: u16 },

    #[error("Connection timed out to {ip}:{port}")]
    Timeout { ip: IpAddr, port: u16 },

    #[error("Host unreachable: {ip}")]
    HostUnreachable { ip: IpAddr },

    #[error("Network unreachable")]
    NetworkUnreachable,

    #[error("TCP connection failed to {ip}:{port}: {message}")]
    ConnectionFailed {
        ip: IpAddr,
        port: u16,
        message: String,
    },
}

/// SSL/TLS protocol errors
#[derive(Error, Debug)]
pub enum SslError {
    #[error("SSL handshake failed: {message}")]
    HandshakeFailed { message: String },

    #[error("No common protocols supported by {ip}:{port}")]
    NoCommonProtocol { ip: IpAddr, port: u16 },

    #[error("No common cipher suites with {ip}:{port}")]
    NoCommonCipher { ip: IpAddr, port: u16 },

    #[error("Protocol {protocol} not supported by server")]
    ProtocolNotSupported { protocol: String },

    #[error("TLS configuration error: {message}")]
    ConfigurationError { message: String },

    #[error("SSL connection error: {message}")]
    ConnectionError { message: String },
}

/// Certificate parsing and validation errors
#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("Certificate has expired")]
    Expired,

    #[error("Certificate not yet valid")]
    NotYetValid,

    #[error("Certificate hostname mismatch: expected {expected}, got {actual}")]
    HostnameMismatch { expected: String, actual: String },

    #[error("Certificate chain validation failed: {message}")]
    ChainValidationFailed { message: String },

    #[error("Self-signed certificate detected")]
    SelfSigned,

    #[error("Certificate revoked")]
    Revoked,

    #[error("Failed to parse certificate: {message}")]
    ParseError { message: String },

    #[error("Certificate missing required extension: {extension}")]
    MissingExtension { extension: String },

    #[error("Weak key detected: {key_type} with {bits} bits")]
    WeakKey { key_type: String, bits: u32 },
}

/// Configuration loading errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration file not found: {path}")]
    FileNotFound { path: String },

    #[error("Failed to parse configuration: {message}")]
    ParseError { message: String },

    #[error("Invalid configuration value for {key}: {message}")]
    InvalidValue { key: String, message: String },

    #[error("Missing required configuration: {key}")]
    MissingRequired { key: String },
}

/// Report generation errors
#[derive(Error, Debug)]
pub enum ReportError {
    #[error("Template rendering failed: {message}")]
    TemplateError { message: String },

    #[error("Failed to write report to {path}: {message}")]
    WriteError { path: String, message: String },

    #[error("Failed to encode asset: {asset}")]
    AssetEncodingError { asset: String },

    #[error("Invalid output format: {format}")]
    InvalidFormat { format: String },
}

/// WHOIS lookup errors
#[derive(Error, Debug)]
pub enum WhoisError {
    #[error("WHOIS lookup failed for {domain}: {message}")]
    LookupFailed { domain: String, message: String },

    #[error("WHOIS rate limited, retry after {seconds} seconds")]
    RateLimited { seconds: u64 },

    #[error("Failed to parse WHOIS response for {domain}")]
    ParseError { domain: String },

    #[error("WHOIS server not found for TLD: {tld}")]
    ServerNotFound { tld: String },

    #[error("WHOIS connection timed out for {domain}")]
    Timeout { domain: String },
}

/// Result type alias using ToolkitError
pub type Result<T> = std::result::Result<T, ToolkitError>;
