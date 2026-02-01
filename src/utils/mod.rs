//! Utility modules for SSL-Toolkit
//!
//! This module contains error types, progress indicators, and other utilities.

pub mod error;
pub mod progress;

pub use error::{
    CertFileError, CertificateError, ConfigError, DnsError, OcspError, ReportError, Result,
    SslError, TcpError, ToolkitError, WhoisError,
};
