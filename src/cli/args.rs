//! CLI argument definitions using Clap derive macros
//!
//! Defines all command-line options for the SSL-Toolkit application.

use clap::{Parser, Subcommand, ValueEnum};
use std::net::IpAddr;
use std::path::PathBuf;

/// SSL/TLS diagnostic tool with polished CLI interface
///
/// Performs comprehensive SSL/TLS analysis including DNS resolution,
/// certificate validation, protocol checks, and cipher suite enumeration.
#[derive(Parser, Debug)]
#[command(name = "ssl-toolkit")]
#[command(author = "Russ McKendrick")]
#[command(version)]
#[command(about = "SSL/TLS diagnostic tool with polished CLI interface")]
#[command(long_about = None)]
pub struct Cli {
    /// Domain name to check (e.g., example.com)
    ///
    /// Can include or omit the protocol prefix. Subdomains are supported.
    /// If omitted, you'll be prompted interactively.
    #[arg(short, long)]
    pub domain: Option<String>,

    /// Override IP address (bypass DNS resolution)
    ///
    /// Use this to test a specific server IP directly, useful for
    /// testing servers behind load balancers or CDNs.
    #[arg(short, long)]
    pub ip: Option<IpAddr>,

    /// Port to connect to
    ///
    /// Standard HTTPS uses 443. Other common ports: 8443, 4443.
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Output results as JSON (implies non-interactive)
    #[arg(long)]
    pub json: bool,

    /// Minimal output - just the grade
    #[arg(short, long)]
    pub quiet: bool,

    /// Skip interactive prompts, auto-select first IP
    #[arg(long)]
    pub non_interactive: bool,

    /// Output HTML report to specified path
    ///
    /// Generates a self-contained HTML report with all check results,
    /// embedded styles, and downloadable certificates.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Verbose output (show detailed check information)
    #[arg(short, long)]
    pub verbose: bool,

    /// Skip WHOIS lookup
    #[arg(long)]
    pub skip_whois: bool,

    /// Connection timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Custom configuration file path
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Subcommand for certificate file operations
    #[command(subcommand)]
    pub command: Option<SubCommand>,
}

/// Subcommands for ssl-toolkit
#[derive(Subcommand, Debug)]
pub enum SubCommand {
    /// Certificate file operations (inspect, verify, convert)
    Cert {
        #[command(subcommand)]
        action: CertAction,
    },
}

/// Actions for the cert subcommand
#[derive(Subcommand, Debug)]
pub enum CertAction {
    /// Inspect certificate file(s) and display details
    Info(CertInfoArgs),

    /// Verify certificate/key pairs or certificate chains
    Verify(CertVerifyArgs),

    /// Convert certificates between PEM, DER, and PKCS#12 formats
    Convert(CertConvertArgs),
}

/// Arguments for `cert info`
#[derive(Parser, Debug)]
pub struct CertInfoArgs {
    /// Certificate file(s) to inspect (PEM, DER, or PKCS#12)
    #[arg(required = true)]
    pub files: Vec<PathBuf>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// PKCS#12 password (if inspecting a .p12/.pfx file)
    #[arg(long)]
    pub password: Option<String>,
}

/// Arguments for `cert verify`
#[derive(Parser, Debug)]
pub struct CertVerifyArgs {
    /// Certificate file to verify
    #[arg(long)]
    pub cert: Option<PathBuf>,

    /// Private key file (for key-pair matching)
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Certificate chain file (for chain validation)
    #[arg(long)]
    pub chain: Option<PathBuf>,

    /// Expected hostname (for chain hostname validation)
    #[arg(long)]
    pub hostname: Option<String>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for `cert convert`
#[derive(Parser, Debug)]
pub struct CertConvertArgs {
    /// Input file to convert
    #[arg()]
    pub input: Option<PathBuf>,

    /// Target format
    #[arg(long, value_name = "FORMAT")]
    pub to: CertFormat,

    /// Output file path (defaults to input filename with new extension)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Certificate file (for PEM → PKCS#12 conversion)
    #[arg(long)]
    pub cert: Option<PathBuf>,

    /// Private key file (for PEM → PKCS#12 conversion)
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// PKCS#12 password
    #[arg(long)]
    pub password: Option<String>,
}

/// Supported certificate formats
#[derive(Debug, Clone, ValueEnum)]
pub enum CertFormat {
    /// PEM format (Base64 encoded with headers)
    Pem,
    /// DER format (binary ASN.1)
    Der,
    /// PKCS#12 format (bundled cert + key)
    P12,
}

impl Cli {
    /// Parse command-line arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Check if running in interactive mode
    pub fn is_interactive(&self) -> bool {
        !self.json && !self.quiet && !self.non_interactive && console::Term::stdout().is_term()
    }

    /// Check if a domain was provided
    pub fn has_domain(&self) -> bool {
        self.domain.is_some()
    }

    /// Check if the port was explicitly set via CLI
    pub fn port_was_set(&self) -> bool {
        self.port.is_some()
    }

    /// Get the port, defaulting to 443
    pub fn port_or_default(&self) -> u16 {
        self.port.unwrap_or(443)
    }

    /// Get the domain, normalizing it (removing protocol prefix if present)
    pub fn normalized_domain(&self) -> Option<String> {
        self.domain.as_ref().map(|d| {
            let d = d.trim();
            let d = d.strip_prefix("https://").unwrap_or(d);
            let d = d.strip_prefix("http://").unwrap_or(d);
            let d = d.strip_suffix('/').unwrap_or(d);
            d.to_lowercase()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
