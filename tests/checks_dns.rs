use ssl_toolkit::checks::DnsChecker;
use ssl_toolkit::config::settings::DnsProvider;

#[tokio::test]
async fn test_resolve_known_domain() {
    let providers = vec![DnsProvider {
        name: "Google".to_string(),
        servers: vec!["8.8.8.8".parse().unwrap()],
        description: "Google DNS".to_string(),
    }];

    let checker = DnsChecker::new(providers);
    let results = checker.resolve_all("google.com").await;

    assert!(!results.is_empty());
    assert!(results[0].is_success());
    assert!(!results[0].addresses.is_empty());
}

#[tokio::test]
async fn test_resolve_invalid_domain() {
    let providers = vec![DnsProvider {
        name: "Google".to_string(),
        servers: vec!["8.8.8.8".parse().unwrap()],
        description: "Google DNS".to_string(),
    }];

    let checker = DnsChecker::new(providers);
    let results = checker
        .resolve_all("this-domain-does-not-exist-12345.invalid")
        .await;

    assert!(!results.is_empty());
    assert!(!results[0].is_success());
}
