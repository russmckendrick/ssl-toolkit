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