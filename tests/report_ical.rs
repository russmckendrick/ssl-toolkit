use chrono::{TimeZone, Utc};
use ssl_toolkit::models::CertificateInfo;
use ssl_toolkit::report::IcalGenerator;

#[test]
fn test_generate_ical() {
    let cert = CertificateInfo {
        subject: "CN=example.com".to_string(),
        issuer: "CN=Test CA".to_string(),
        serial: "01".to_string(),
        thumbprint: "AA:BB:CC".to_string(),
        not_before: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        not_after: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
        san: vec!["example.com".to_string()],
        public_key_algorithm: "RSA".to_string(),
        public_key_size: 2048,
        signature_algorithm: "SHA256withRSA".to_string(),
        is_self_signed: false,
        is_ca: false,
        version: 3,
        key_usage: vec![],
        extended_key_usage: vec![],
        raw_der: vec![],
        ocsp_responder_url: None,
        crl_distribution_points: vec![],
        revocation: None,
    };

    let ical = IcalGenerator::generate("example.com", &cert);
    assert!(ical.contains("BEGIN:VCALENDAR"));
    assert!(ical.contains("SSL Certificate Expires"));
    assert!(ical.contains("END:VCALENDAR"));
}
