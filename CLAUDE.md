# SSL-Toolkit - Claude Code Memory

## Project Overview

SSL/TLS diagnostic tool built in Rust combining an interactive main menu, CLI prompts, and a ratatui-based pager for output. When run with no arguments, presents a top-level menu offering domain checks, certificate file inspection, verification, and conversion. All operations display results in the scrollable TUI pager. Also supports direct CLI usage with flags and subcommands for non-interactive workflows.

## Quick Reference

### Code Quality Commands (Run Before Every Commit)

```bash
cargo fmt          # Format code
cargo clippy       # Lint for issues
cargo check        # Type check
cargo test         # Run tests
cargo doc --open   # Generate docs
```

### Build & Run

```bash
cargo run --                                        # Interactive menu mode
cargo run -- --domain example.com                   # Direct domain check (interactive)
cargo run -- --domain example.com --non-interactive  # Non-interactive mode
cargo run -- --domain example.com --json             # JSON output
cargo run -- --domain example.com --quiet            # Quiet mode (grade only)
cargo run -- --help                                  # Show options
```

### Interactive Menu Mode (no arguments)

Running `ssl-toolkit` with no arguments and a TTY shows a top-level menu:

```
? What would you like to do?
❯ Check a domain
  Inspect certificate file(s)
  Verify certificate & key
  Convert certificate format
  Quit
```

Each option prompts for the required inputs (domain, files, etc.), runs the operation, and displays results in the ratatui pager. After each operation, a post-operation prompt offers "Run another check" or "Quit".

For domain checks, the pager `n` key returns directly to the main menu. For cert operations, quitting the pager shows the post-operation prompt.

### Certificate File Operations (`cert` subcommand)

```bash
cargo run -- cert info cert.pem                                    # Inspect cert file(s)
cargo run -- cert info cert.pem chain.pem --json                   # JSON output
cargo run -- cert verify --cert cert.pem --key key.pem             # Check key matches cert
cargo run -- cert verify --chain chain.pem --hostname example.com  # Validate chain
cargo run -- cert convert cert.pem --to der                        # PEM → DER
cargo run -- cert convert cert.pem --to der -o cert.der            # Explicit output path
cargo run -- cert convert --to p12 --cert c.pem --key k.pem        # PEM → PKCS#12
cargo run -- cert convert bundle.p12 --to pem --password pass      # PKCS#12 → PEM
```

## Architecture

```
src/
├── main.rs              # Entry point, interactive menu loop, CLI dispatch
├── lib.rs               # Public API exports
├── runner.rs            # Check orchestration engine
├── cli/args.rs          # Clap argument definitions (+ SubCommand, CertAction enums)
├── cert_ops/            # Certificate file operations
│   ├── mod.rs           # Module declarations
│   ├── reader.rs        # Format detection & certificate reading (PEM/DER/PKCS#12)
│   ├── key_match.rs     # Private key parsing & cert/key pair matching
│   ├── chain_verify.rs  # Certificate chain integrity validation
│   ├── convert.rs       # Format conversion (PEM↔DER↔PKCS#12)
│   └── runner.rs        # Orchestrates cert info/verify/convert (CLI + interactive/pager)
├── config/              # Configuration loading
│   ├── mod.rs
│   ├── settings.rs      # DNS providers, SSL timeouts, WHOIS settings
│   ├── theme.rs         # Theme loading & types
│   └── messages.rs      # Message template loading
├── checks/              # Core diagnostic modules
│   ├── whois.rs         # WHOIS lookups
│   ├── dns.rs           # Multi-provider DNS resolution
│   ├── tcp.rs           # Port connectivity tests
│   ├── ssl.rs           # SSL/TLS protocol & cipher checks
│   └── certificate.rs   # Certificate parsing & validation
├── models/              # Data structures
│   ├── dns_result.rs
│   ├── ssl_result.rs
│   ├── certificate.rs
│   ├── cert_comparison.rs # Certificate comparison across IPs
│   ├── test_result.rs
│   └── report_card.rs
├── output/              # CLI output formatting
│   ├── banner.rs        # ASCII art banner
│   ├── interactive.rs   # Dialoguer prompts (main menu, domain, IP, port, cert ops)
│   ├── results.rs       # Formatted result display
│   ├── tables.rs        # Table formatting (comfy-table)
│   ├── grade.rs         # Grade display (A+ through F)
│   ├── cert_chain.rs    # Certificate chain visualization
│   ├── json.rs          # JSON output mode
│   └── pager.rs         # Ratatui scrollable viewer
├── report/              # HTML, iCal, PEM generation
└── utils/               # Progress indicators, error types
```

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `clap` | CLI parsing (derive macros) |
| `tokio` | Async runtime (full features) |
| `ratatui` + `crossterm` | Pager view (scrollable results) |
| `dialoguer` + `console` | Interactive CLI prompts |
| `comfy-table` | Table formatting |
| `hickory-resolver` | Async DNS resolution |
| `rustls` | Modern TLS (TLS 1.2/1.3) |
| `native-tls` | Legacy protocol detection (SSLv3, TLS 1.0/1.1) |
| `x509-parser` | Certificate parsing |
| `unicode-width` | **Critical** for output alignment |
| `minijinja` | HTML report templating |
| `icalendar` | Calendar reminder generation |
| `chrono` | Date/time with timezone |
| `serde_json` | JSON output |
| `indicatif` | Progress indicators |
| `base64` | PEM/data URI encoding |
| `whois-rust` | WHOIS lookups (node-whois servers.json) |
| `pem` | PEM block parsing (CERTIFICATE, PRIVATE KEY) |
| `pkcs8` | Private key parsing (PKCS#8) |
| `rsa` | RSA key matching |
| `p256` / `p384` | EC key matching (P-256, P-384) |
| `p12-keystore` | PKCS#12 read/write (pure Rust) |
| `ansi-to-tui` | ANSI text in ratatui pager |
| `tracing` | Structured logging |
| `thiserror` + `anyhow` | Error handling |

## Critical: Output Alignment

All output borders MUST be correctly aligned. Use these patterns:

```rust
use unicode_width::UnicodeWidthStr;

/// Calculate display width accounting for Unicode
fn display_width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// Pad string to exact display width
fn pad_to_width(s: &str, width: usize) -> String {
    let current = display_width(s);
    if current >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - current))
    }
}
```

### Alignment Rules

1. Use `unicode-width` for all width calculations
2. Exactly 2 spaces padding inside box edges
3. Inner boxes inset by exactly 3 characters from outer boxes
4. Calculate terminal width dynamically - never assume 80 columns
5. Test on iTerm2, Terminal.app, Windows Terminal, Linux terminals

## Core Data Structures

### Check Status

```rust
pub enum CheckStatus { Pass, Warning, Fail }
```

### Test Result (verbose output style)

```rust
pub struct TestResult {
    pub title: String,           // Header text
    pub status: CheckStatus,
    pub summary: String,         // One-line after status icon
    pub details: Vec<DetailSection>,
    pub test_steps: Vec<TestStep>,
    pub recommendations: Vec<String>,
}
```

### Detail Sections

```rust
pub enum DetailSection {
    KeyValue { title: Option<String>, pairs: Vec<(String, String)> },
    Table { title: Option<String>, headers: Vec<String>, rows: Vec<Vec<String>> },
    List { title: Option<String>, items: Vec<String> },
    Text { title: Option<String>, content: String },
    CertificateChain { certificates: Vec<CertificateSummary> },
}
```

## CLI Arguments

```rust
#[derive(Parser)]
pub struct Cli {
    #[arg(short, long)]
    pub domain: Option<String>,      // Domain to check

    #[arg(short, long)]
    pub ip: Option<IpAddr>,          // Override IP (bypass DNS)

    #[arg(short, long)]
    pub port: Option<u16>,           // Custom port (default: 443)

    #[arg(long)]
    pub json: bool,                  // JSON output (implies non-interactive)

    #[arg(short, long)]
    pub quiet: bool,                 // Minimal output - just the grade

    #[arg(long)]
    pub non_interactive: bool,       // Skip interactive prompts

    #[arg(short, long)]
    pub output: Option<PathBuf>,     // HTML report path

    #[arg(short, long)]
    pub verbose: bool,               // Detailed check information

    #[arg(long)]
    pub skip_whois: bool,            // Skip WHOIS lookup

    #[arg(long, default_value = "10")]
    pub timeout: u64,                // Connection timeout in seconds

    #[arg(long)]
    pub config: Option<PathBuf>,     // Custom config file path
}
```

## Configuration Files

- `config/default.toml` - DNS providers, SSL settings
- `config/theme.toml` - Icons, colors, box characters
- `config/messages.toml` - All user-facing text templates

### Theme Icons

```toml
pass = "✓"    fail = "✗"    warning = "!"
info = "i"    critical = "X"
cert_leaf = "📄"    cert_intermediate = "⛓"    cert_root = "🔒"
```

### Theme Colors (Tokyo Night Storm)

```toml
pass = "#9ece6a"    fail = "#f7768e"    warning = "#e0af68"
info = "#7dcfff"    primary = "#7aa2f7"
secondary = "#a9b1d6"    background = "#24283b"
foreground = "#c0caf5"    border = "#565f89"    highlight = "#bb9af7"
```

## TLS Protocol Detection

- **Modern protocols (TLS 1.2, 1.3)**: Use `rustls`
- **Legacy protocols (SSLv3, TLS 1.0, 1.1)**: Use `native-tls` or raw socket probing

## Testing Strategy

```rust
#[tokio::test]
async fn test_ssl_check_expired_cert() {
    // Use badssl.com test endpoints:
    // - expired.badssl.com
    // - wrong.host.badssl.com
    // - self-signed.badssl.com
}
```

## Documentation Requirements

Maintain docs in `docs/` folder:
- `architecture.md` - High-level overview with mermaid diagrams
- `checks.md` - Detailed check module documentation
- `configuration.md` - Configuration file format guide

## CI/CD Pipeline

### Release Workflow (`.github/workflows/release.yml`)

Triggered by pushing a `v*` tag. Uses a matrix strategy to build natively on each platform:

| Target | Runner | Artifact Name |
|--------|--------|---------------|
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` | `ssl-toolkit-linux-amd64` |
| `x86_64-apple-darwin` | `macos-latest` | `ssl-toolkit-darwin-amd64` |
| `aarch64-apple-darwin` | `macos-latest` | `ssl-toolkit-darwin-arm64` |
| `x86_64-pc-windows-msvc` | `windows-latest` | `ssl-toolkit-windows-amd64.exe` |

Native builds are required because `native-tls` links against platform-specific TLS libraries (OpenSSL on Linux, Security.framework on macOS, SChannel on Windows).

Tests run on the Linux job only. SHA256 checksums are generated for all binaries. The release job collects all artifacts and creates a GitHub Release with `softprops/action-gh-release`.

### Homebrew Tap Workflow (`.github/workflows/update-tap.yml`)

Triggered when a release is published. Downloads the macOS SHA256 checksums and updates the formula in the `homebrew-tap` repository. Artifact names must match exactly for this workflow to function.

### Creating a Release

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Best Practices

1. **No code duplication** - Use existing code as templates
2. **Update docs at every step** - Keep documentation current
3. **Prefer editing over creating** - Modify existing files when possible
4. **Test on multiple platforms** - macOS, Linux, Windows
5. **Pager keys**: `↑/k` (up), `↓/j` (down), `s` (save report), `n` (new check / back to menu), `q` (quit pager). The pager is used for both domain check results and certificate file operation results.
6. **Handle network timeouts gracefully** - Use mock servers in tests
7. **Implement WHOIS rate limiting** - Caching + exponential backoff

## Success Criteria

- All checks work against test domains
- Cross-platform builds without modification
- CLI responsive with smooth pager scrolling
- Correct border alignment across terminals
- HTML reports work in major browsers
- >80% code coverage on core modules
