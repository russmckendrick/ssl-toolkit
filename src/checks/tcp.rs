//! TCP connectivity checker
//!
//! Tests TCP connection to a given IP and port.

use crate::utils::TcpError;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// TCP connectivity checker
pub struct TcpChecker {
    timeout: Duration,
}

impl TcpChecker {
    /// Create a new TCP checker with the given timeout
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Check TCP connectivity to the given IP and port
    ///
    /// Returns the connection time on success, or an error on failure
    pub async fn check(&self, ip: IpAddr, port: u16) -> Result<Duration, TcpError> {
        let addr = std::net::SocketAddr::new(ip, port);
        let start = Instant::now();

        match tokio::time::timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => Ok(start.elapsed()),
            Ok(Err(e)) => {
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("refused") {
                    Err(TcpError::ConnectionRefused { ip, port })
                } else if error_str.contains("unreachable") {
                    if error_str.contains("network") {
                        Err(TcpError::NetworkUnreachable)
                    } else {
                        Err(TcpError::HostUnreachable { ip })
                    }
                } else {
                    Err(TcpError::ConnectionFailed {
                        ip,
                        port,
                        message: e.to_string(),
                    })
                }
            }
            Err(_) => Err(TcpError::Timeout { ip, port }),
        }
    }

    /// Check connectivity and return a simple boolean
    pub async fn is_reachable(&self, ip: IpAddr, port: u16) -> bool {
        self.check(ip, port).await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
