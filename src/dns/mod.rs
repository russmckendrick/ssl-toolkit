//! DNS module for domain resolution and analysis
//!
//! This module provides functionality for:
//! - DNS record resolution (A, AAAA, MX, TXT, NS, SOA, CAA, SRV)
//! - DANE/TLSA checking
//! - Nameserver consistency checking
//! - IP geolocation
//! - Email security record analysis (SPF, DKIM, DMARC, MTA-STS, BIMI)

pub mod geolocation;
pub mod records;
pub mod resolver;
pub mod tlsa;

pub use geolocation::{get_geolocation, get_geolocations, GeoLocation};
pub use records::{
    CaaRecord, DnsInfo, MtaStsRecord, MxRecord, NameserverCheck, SoaRecord, SrvRecord,
    TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage,
};
pub use resolver::DnsResolver;
pub use tlsa::{
    format_tlsa_for_zone, generate_tlsa_record, lookup_tlsa_records,
    validate_certificate_against_tlsa, DaneValidationResult,
};
