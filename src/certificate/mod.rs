//! Certificate handling module
//!
//! This module provides functionality for:
//! - Retrieving SSL certificates from domains
//! - Parsing certificate information
//! - Chain validation and completion
//! - OCSP and CRL checking
//! - Security scoring
//! - Calendar reminder generation

pub mod calendar;
pub mod chain;
pub mod info;
pub mod security;
pub mod validation;

pub use chain::{complete_chain_via_aia, export_chain_as_pem, get_certificate_chain, parse_certificate};
pub use info::{
    AuthorityInfoAccess, CertificateChain, CertificateInfo, DistinguishedName, KeyAlgorithm,
    OcspStatus, SslCheckResult, TrustStatus,
};
pub use security::{calculate_security_grade, generate_security_summary, GradeFactor, SecurityGrade};
pub use validation::{check_crl_status, check_ocsp_status, validate_against_trust_store};
pub use calendar::{generate_ical_reminder, save_ical_file, generate_ical_filename};
