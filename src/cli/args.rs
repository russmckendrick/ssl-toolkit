//! CLI argument definitions using clap

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ssl-toolkit")]
#[command(author = "Russ McKendrick")]
#[command(version)]
#[command(about = "A comprehensive SSL/TLS certificate analysis toolkit", long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Domain to check (shortcut for 'check' command)
    #[arg(value_name = "DOMAIN")]
    pub domain: Option<String>,

    /// Interactive mode
    #[arg(short, long)]
    pub interactive: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub format: OutputFormat,

    /// Write output to file
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Minimal output (exit code only)
    #[arg(short, long)]
    pub quiet: bool,

    /// Check certificate at specific IP address
    #[arg(long, value_name = "IP")]
    pub ip: Option<String>,

    /// Custom port (default: 443)
    #[arg(long, default_value = "443")]
    pub port: u16,

    /// Connection timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,

    /// Download certificate chain as PEM
    #[arg(long)]
    pub download_chain: bool,

    /// Create iCal expiry reminder
    #[arg(long)]
    pub create_reminder: bool,

    /// Days before expiry for reminder
    #[arg(long, default_value = "30")]
    pub reminder_days: i64,

    /// Skip DNS information lookup
    #[arg(long)]
    pub skip_dns: bool,

    /// Skip CT log lookup
    #[arg(long)]
    pub skip_ct: bool,

    /// Skip OCSP checking
    #[arg(long)]
    pub skip_ocsp: bool,

    /// Show security grade only
    #[arg(long)]
    pub grade: bool,

    /// Show chain details only
    #[arg(long)]
    pub chain: bool,

    /// Show DNS details only
    #[arg(long)]
    pub dns: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Check SSL certificate for a domain
    Check(CheckArgs),

    /// Check multiple domains from a file
    Batch(BatchArgs),

    /// Monitor certificate for changes
    Watch(WatchArgs),

    /// Compare two certificates
    Diff(DiffArgs),

    /// List certificates expiring soon
    Expiring(ExpiringArgs),

    /// List available root certificates
    ListRoots,

    /// Search Certificate Transparency logs
    CtSearch(CtSearchArgs),

    /// Generate TLSA/DANE record
    Tlsa(TlsaArgs),
}

#[derive(Args)]
pub struct CheckArgs {
    /// Domain to check
    #[arg(required = true)]
    pub domain: String,

    /// Check certificate at specific IP address
    #[arg(long, value_name = "IP")]
    pub ip: Option<String>,

    /// Custom port
    #[arg(long, default_value = "443")]
    pub port: u16,

    /// Connection timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Skip DNS information lookup
    #[arg(long)]
    pub skip_dns: bool,

    /// Skip CT log lookup
    #[arg(long)]
    pub skip_ct: bool,

    /// Skip OCSP checking
    #[arg(long)]
    pub skip_ocsp: bool,

    /// Download certificate chain as PEM
    #[arg(long)]
    pub download_chain: bool,

    /// Create iCal expiry reminder
    #[arg(long)]
    pub create_reminder: bool,

    /// Days before expiry for reminder
    #[arg(long, default_value = "30")]
    pub reminder_days: i64,
}

#[derive(Args)]
pub struct BatchArgs {
    /// File containing domains (one per line)
    #[arg(required = true)]
    pub file: PathBuf,

    /// Number of parallel checks
    #[arg(short, long, default_value = "5")]
    pub parallel: usize,

    /// Connection timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Skip DNS information lookup
    #[arg(long)]
    pub skip_dns: bool,

    /// Skip CT log lookup
    #[arg(long)]
    pub skip_ct: bool,

    /// Skip OCSP checking
    #[arg(long)]
    pub skip_ocsp: bool,

    /// Only show domains with issues
    #[arg(long)]
    pub issues_only: bool,
}

#[derive(Args)]
pub struct WatchArgs {
    /// Domain to watch
    #[arg(required = true)]
    pub domain: String,

    /// Check interval in seconds
    #[arg(short, long, default_value = "300")]
    pub interval: u64,

    /// Number of checks (0 = infinite)
    #[arg(short, long, default_value = "0")]
    pub count: u64,

    /// Alert on certificate change
    #[arg(long)]
    pub alert_on_change: bool,

    /// Alert when expiry is within days
    #[arg(long)]
    pub alert_expiry_days: Option<i64>,
}

#[derive(Args)]
pub struct DiffArgs {
    /// First domain or certificate file
    #[arg(required = true)]
    pub first: String,

    /// Second domain or certificate file (or --ip for same domain different IP)
    #[arg(required_unless_present = "ip")]
    pub second: Option<String>,

    /// Compare with certificate at specific IP
    #[arg(long, value_name = "IP")]
    pub ip: Option<String>,

    /// Custom port
    #[arg(long, default_value = "443")]
    pub port: u16,
}

#[derive(Args)]
pub struct ExpiringArgs {
    /// File containing domains, or omit for stdin
    pub file: Option<PathBuf>,

    /// Days threshold for expiring soon
    #[arg(short, long, default_value = "30")]
    pub days: i64,

    /// Number of parallel checks
    #[arg(short, long, default_value = "5")]
    pub parallel: usize,

    /// Sort by expiry date
    #[arg(long)]
    pub sort: bool,
}

#[derive(Args)]
pub struct CtSearchArgs {
    /// Domain to search
    #[arg(required = true)]
    pub domain: String,

    /// Include expired certificates
    #[arg(long)]
    pub include_expired: bool,

    /// Maximum number of results
    #[arg(short, long, default_value = "100")]
    pub limit: usize,

    /// Filter by issuer name
    #[arg(long)]
    pub issuer: Option<String>,
}

#[derive(Args)]
pub struct TlsaArgs {
    /// Domain to generate TLSA for
    #[arg(required = true)]
    pub domain: String,

    /// Port
    #[arg(long, default_value = "443")]
    pub port: u16,

    /// TLSA usage (0-3)
    #[arg(long, default_value = "3")]
    pub usage: u8,

    /// TLSA selector (0-1)
    #[arg(long, default_value = "1")]
    pub selector: u8,

    /// TLSA matching type (0-2)
    #[arg(long, default_value = "1")]
    pub matching_type: u8,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum OutputFormat {
    /// Rich terminal tables (default)
    Table,
    /// JSON output
    Json,
    /// Markdown report
    Markdown,
    /// HTML report
    Html,
    /// Plain text (minimal formatting)
    Plain,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Table => write!(f, "table"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Markdown => write!(f, "markdown"),
            OutputFormat::Html => write!(f, "html"),
            OutputFormat::Plain => write!(f, "plain"),
        }
    }
}
