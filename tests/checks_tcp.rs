use ssl_toolkit::checks::TcpChecker;
use std::time::Duration;

#[tokio::test]
async fn test_tcp_connect_google() {
    let checker = TcpChecker::new(Duration::from_secs(5));
    let result = checker.check("142.250.80.46".parse().unwrap(), 443).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_tcp_connect_refused() {
    let checker = TcpChecker::new(Duration::from_secs(2));
    // Port 1 is typically not open
    let result = checker.check("127.0.0.1".parse().unwrap(), 1).await;
    assert!(result.is_err());
}
