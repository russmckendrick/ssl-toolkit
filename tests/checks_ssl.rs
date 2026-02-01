use ssl_toolkit::checks::SslChecker;
use ssl_toolkit::config::settings::SslSettings;

#[tokio::test]
async fn test_ssl_check_google() {
    let settings = SslSettings::default();
    let checker = SslChecker::new(settings);

    let result = checker
        .check("google.com", "142.250.80.46".parse().unwrap(), 443)
        .await;

    assert!(result.is_ok());
    let info = result.unwrap();
    assert!(info.protocol.is_secure());
    assert!(!info.certificate_chain.is_empty());
}
