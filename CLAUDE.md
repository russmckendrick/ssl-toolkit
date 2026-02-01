# SSL-Toolkit - Claude Code Memory

## Project Overview

SSL/TLS diagnostic tool built in Rust combining interactive CLI prompts with a ratatui-based pager for output. Performs domain validation, DNS resolution across multiple providers, and SSL certificate analysis with exportable HTML reports.

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
cargo run -- --domain example.com                  # Interactive mode
cargo run -- --domain example.com --non-interactive # Non-interactive mode
cargo run -- --domain example.com --json            # JSON output
cargo run -- --domain example.com --quiet           # Quiet mode (grade only)
cargo run -- --help                                 # Show options
```

## Architecture

```
src/
├── main.rs              # Entry point & CLI parsing
├── lib.rs               # Public API exports
├── runner.rs            # Check orchestration engine
├── cli/args.rs          # Clap argument definitions
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
│   ├── interactive.rs   # Dialoguer prompts (domain, IP, port)
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
5. **Pager keys**: `↑/k` (up), `↓/j` (down), `s` (save), `n` (new check), `q` (quit)
6. **Handle network timeouts gracefully** - Use mock servers in tests
7. **Implement WHOIS rate limiting** - Caching + exponential backoff

## Success Criteria

- All checks work against test domains
- Cross-platform builds without modification
- CLI responsive with smooth pager scrolling
- Correct border alignment across terminals
- HTML reports work in major browsers
- >80% code coverage on core modules
