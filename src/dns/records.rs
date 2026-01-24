//! DNS record types and structures

use serde::{Deserialize, Serialize};

/// Complete DNS information for a domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub domain: String,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub nameservers: Vec<String>,
    pub mx_records: Vec<MxRecord>,
    pub txt_records: Vec<String>,
    pub caa_records: Vec<CaaRecord>,
    pub srv_records: Vec<SrvRecord>,
    pub soa_record: Option<SoaRecord>,
    pub nameserver_checks: Vec<NameserverCheck>,
    pub is_consistent: bool,
    pub dnssec_enabled: bool,
    pub tlsa_records: Vec<TlsaRecord>,
    pub spf_record: Option<String>,
    pub dmarc_record: Option<String>,
    pub dkim_selector: Option<String>,
    pub mta_sts: Option<MtaStsRecord>,
    pub bimi_record: Option<String>,
}

impl Default for DnsInfo {
    fn default() -> Self {
        DnsInfo {
            domain: String::new(),
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            nameservers: Vec::new(),
            mx_records: Vec::new(),
            txt_records: Vec::new(),
            caa_records: Vec::new(),
            srv_records: Vec::new(),
            soa_record: None,
            nameserver_checks: Vec::new(),
            is_consistent: true,
            dnssec_enabled: false,
            tlsa_records: Vec::new(),
            spf_record: None,
            dmarc_record: None,
            dkim_selector: None,
            mta_sts: None,
            bimi_record: None,
        }
    }
}

/// MX record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

impl std::fmt::Display for MxRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.preference, self.exchange)
    }
}

/// CAA (Certification Authority Authorization) record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaRecord {
    pub flags: u8,
    pub tag: String,
    pub value: String,
}

impl std::fmt::Display for CaaRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} \"{}\"", self.flags, self.tag, self.value)
    }
}

/// SRV record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrvRecord {
    pub service: String,
    pub protocol: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

impl std::fmt::Display for SrvRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "_{}._{} {} {} {} {}",
            self.service, self.protocol, self.priority, self.weight, self.port, self.target
        )
    }
}

/// SOA (Start of Authority) record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoaRecord {
    pub primary_ns: String,
    pub responsible_party: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum_ttl: u32,
}

impl std::fmt::Display for SoaRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {}",
            self.primary_ns,
            self.responsible_party,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum_ttl
        )
    }
}

/// TLSA record for DANE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsaRecord {
    pub usage: TlsaUsage,
    pub selector: TlsaSelector,
    pub matching_type: TlsaMatchingType,
    pub certificate_data: String,
}

impl std::fmt::Display for TlsaRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.usage as u8, self.selector as u8, self.matching_type as u8, self.certificate_data
        )
    }
}

/// TLSA certificate usage field
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum TlsaUsage {
    CaPkixTa = 0,      // CA constraint
    ServicePkixEe = 1, // Service certificate constraint
    TrustAnchorAssertion = 2, // Trust anchor assertion
    DomainIssuedCertificate = 3, // Domain-issued certificate
}

impl TlsaUsage {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TlsaUsage::CaPkixTa),
            1 => Some(TlsaUsage::ServicePkixEe),
            2 => Some(TlsaUsage::TrustAnchorAssertion),
            3 => Some(TlsaUsage::DomainIssuedCertificate),
            _ => None,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            TlsaUsage::CaPkixTa => "CA constraint (PKIX-TA)",
            TlsaUsage::ServicePkixEe => "Service certificate constraint (PKIX-EE)",
            TlsaUsage::TrustAnchorAssertion => "Trust anchor assertion (DANE-TA)",
            TlsaUsage::DomainIssuedCertificate => "Domain-issued certificate (DANE-EE)",
        }
    }
}

/// TLSA selector field
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum TlsaSelector {
    FullCertificate = 0,
    SubjectPublicKeyInfo = 1,
}

impl TlsaSelector {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TlsaSelector::FullCertificate),
            1 => Some(TlsaSelector::SubjectPublicKeyInfo),
            _ => None,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            TlsaSelector::FullCertificate => "Full certificate",
            TlsaSelector::SubjectPublicKeyInfo => "SubjectPublicKeyInfo",
        }
    }
}

/// TLSA matching type field
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum TlsaMatchingType {
    Exact = 0,
    Sha256 = 1,
    Sha512 = 2,
}

impl TlsaMatchingType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TlsaMatchingType::Exact),
            1 => Some(TlsaMatchingType::Sha256),
            2 => Some(TlsaMatchingType::Sha512),
            _ => None,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            TlsaMatchingType::Exact => "Exact match",
            TlsaMatchingType::Sha256 => "SHA-256 hash",
            TlsaMatchingType::Sha512 => "SHA-512 hash",
        }
    }
}

/// MTA-STS record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaStsRecord {
    pub version: String,
    pub id: String,
}

impl std::fmt::Display for MtaStsRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v={}; id={}", self.version, self.id)
    }
}

/// Nameserver check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameserverCheck {
    pub nameserver: String,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub response_time_ms: Option<u64>,
    pub error: Option<String>,
}

impl NameserverCheck {
    pub fn is_successful(&self) -> bool {
        self.error.is_none()
    }
}
