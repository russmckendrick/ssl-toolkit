//! Data models for SSL-Toolkit
//!
//! This module contains all the data structures used throughout the application.

pub mod cert_comparison;
pub mod certificate;
pub mod dns_result;
pub mod report_card;
pub mod ssl_result;
pub mod test_result;

pub use cert_comparison::{CertComparison, CertComparisonEntry, CertDifference};
pub use certificate::{
    CertificateInfo, CertificateSummary, CertificateType, RevocationCheckMethod, RevocationInfo,
    RevocationStatus,
};
pub use dns_result::DnsResult;
pub use report_card::{Grade, ReportCard};
pub use ssl_result::{CipherSuite, ProtocolSupport, SslInfo, TlsProtocol};
pub use test_result::{CheckStatus, DetailSection, TestResult, TestStep};
