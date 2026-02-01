use ssl_toolkit::cli::Cli;

#[test]
fn test_normalized_domain() {
    let cli = Cli {
        domain: Some("https://Example.COM/".to_string()),
        ip: None,
        port: None,
        json: false,
        quiet: false,
        non_interactive: false,
        output: None,
        verbose: false,
        skip_whois: false,
        timeout: 10,
        config: None,
        command: None,
    };
    assert_eq!(cli.normalized_domain(), Some("example.com".to_string()));
}

#[test]
fn test_is_interactive_with_json() {
    let cli = Cli {
        domain: None,
        ip: None,
        port: None,
        json: true,
        quiet: false,
        non_interactive: false,
        output: None,
        verbose: false,
        skip_whois: false,
        timeout: 10,
        config: None,
        command: None,
    };
    assert!(!cli.is_interactive());
}

#[test]
fn test_is_interactive_with_quiet() {
    let cli = Cli {
        domain: None,
        ip: None,
        port: None,
        json: false,
        quiet: true,
        non_interactive: false,
        output: None,
        verbose: false,
        skip_whois: false,
        timeout: 10,
        config: None,
        command: None,
    };
    assert!(!cli.is_interactive());
}
