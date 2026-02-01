//! SSL-Toolkit Library
//!
//! A comprehensive SSL/TLS diagnostic tool providing:
//! - Domain validation and DNS resolution across multiple providers
//! - TCP connectivity testing
//! - SSL/TLS protocol and cipher suite analysis
//! - Certificate parsing and validation
//! - HTML report generation with embedded downloads
//!
//! # Usage
//!
//! ```rust,ignore
//! use ssl_toolkit::checks::{DnsChecker, SslChecker, CertificateChecker};
//! use ssl_toolkit::models::CheckStatus;
//!
//! #[tokio::main]
//! async fn main() {
//!     let dns = DnsChecker::new();
//!     let results = dns.resolve_all("example.com").await;
//!     // Process results...
//! }
//! ```

pub mod checks;
pub mod cli;
pub mod config;
pub mod models;
pub mod output;
pub mod report;
pub mod runner;
pub mod utils;

// Re-export commonly used types
pub use cli::Cli;
pub use config::{Messages, Settings, Theme};
pub use models::{CheckStatus, ReportCard, TestResult};
pub use utils::{Result, ToolkitError};
