use ssl_toolkit::cert_ops::{detect_format_from_bytes, DetectedFormat};

#[test]
fn test_detect_pem_format() {
    let pem_data = b"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----\n";
    assert_eq!(
        detect_format_from_bytes(pem_data).unwrap(),
        DetectedFormat::Pem
    );
}

#[test]
fn test_detect_unknown_format() {
    let garbage = b"this is not a certificate";
    assert!(detect_format_from_bytes(garbage).is_err());
}
