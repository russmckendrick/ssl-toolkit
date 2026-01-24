//! Unified error types for ssl-toolkit

use thiserror::Error;

/// Main error type for ssl-toolkit operations
#[derive(Error, Debug)]
pub enum SslToolkitError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("OCSP error: {0}")]
    Ocsp(String),

    #[error("CT log error: {0}")]
    CertificateTransparency(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid domain: {0}")]
    InvalidDomain(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("File error: {0}")]
    File(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("{0}")]
    Other(String),
}

impl From<rustls::Error> for SslToolkitError {
    fn from(err: rustls::Error) -> Self {
        SslToolkitError::Tls(err.to_string())
    }
}

impl From<x509_parser::error::X509Error> for SslToolkitError {
    fn from(err: x509_parser::error::X509Error) -> Self {
        SslToolkitError::Certificate(err.to_string())
    }
}

impl From<hickory_resolver::error::ResolveError> for SslToolkitError {
    fn from(err: hickory_resolver::error::ResolveError) -> Self {
        SslToolkitError::Dns(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SslToolkitError>;
