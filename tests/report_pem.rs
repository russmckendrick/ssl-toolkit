use ssl_toolkit::report::PemExporter;

#[test]
fn test_export_chain() {
    let chain = vec![
        vec![0x30, 0x82, 0x01, 0x00], // Minimal DER header
    ];

    let pem = PemExporter::export_chain(&chain);
    assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
    assert!(pem.contains("-----END CERTIFICATE-----"));
}
