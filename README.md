# SSL-Toolkit

A comprehensive SSL/TLS diagnostic tool built in Rust. When run with no arguments, presents an interactive main menu for domain checks and certificate file operations, with all results displayed in a scrollable TUI pager. Also supports direct CLI usage with flags and subcommands for scripting and CI/CD.

## Features

- **Interactive Main Menu**: Top-level menu offering domain checks, certificate inspection, verification, conversion, and quit — all with results in a scrollable TUI pager, themed with the Tokyo Night Storm palette
- **Certificate File Operations**: Inspect, verify (key-pair matching and chain validation), and convert (PEM/DER/PKCS#12) certificate files — available from the menu or via the `cert` subcommand
- **File Path Autocomplete**: Tab-completion on all file path prompts with directories sorted first, dotfile hiding, and cross-platform support
- **Graceful Ctrl+C Handling**: Clean exit at any prompt with no error messages
- **Non-Interactive Mode**: Automated checks for scripting and CI/CD pipelines
- **JSON Output**: Machine-readable output for integration with other tools
- **Quiet Mode**: Minimal output showing just the overall grade
- **Multi-Provider DNS Resolution**: Compare results from Google, Cloudflare, OpenDNS, and system resolver
- **Certificate Analysis**: Parse and validate X.509 certificates with chain verification
- **Certificate Comparison**: Compare certificates across multiple IPs for consistency
- **Grade Scoring**: Overall security grade (A+ through F) based on weighted check results
- **Protocol Detection**: Identify supported TLS versions (1.0, 1.1, 1.2, 1.3)
- **Cipher Suite Analysis**: Enumerate and evaluate cipher suites
- **WHOIS Lookup**: Domain registration information with rate limiting
- **HTML Reports**: Self-contained reports with embedded styles and downloadable certificates
- **Calendar Reminders**: iCal export with certificate expiry reminders

## Installation

### Homebrew (macOS)

```bash
brew tap russmckendrick/tap
brew install ssl-toolkit
```

### From GitHub Releases

Pre-built binaries are available for Linux (x86_64), macOS (x86_64, Apple Silicon), and Windows (x86_64) on the [Releases](https://github.com/russmckendrick/ssl-toolkit/releases) page. Download the appropriate binary for your platform and add it to your `PATH`.

### From Source

```bash
# Clone the repository
git clone https://github.com/russmckendrick/ssl-toolkit.git
cd ssl-toolkit

# Build with cargo
cargo build --release

# Install to PATH
cargo install --path .
```

## Usage

### Interactive Menu Mode

```bash
# Launch the interactive menu
ssl-toolkit
```

This displays a banner and a top-level menu:

```
? What would you like to do?
❯ Check a domain
  Inspect certificate file(s)
  Verify certificate & key
  Convert certificate format
  Quit
```

Each option prompts for the required inputs, runs the operation, and displays results in the scrollable pager. After each operation you can return to the menu or quit.

### Direct Domain Check

```bash
# Launch with pre-filled domain (skips menu, goes straight to domain check)
ssl-toolkit -d example.com
```

### Certificate File Operations (subcommand)

```bash
# Inspect certificate file(s)
ssl-toolkit cert info cert.pem
ssl-toolkit cert info cert.pem chain.pem --json

# Verify key matches certificate
ssl-toolkit cert verify --cert cert.pem --key key.pem

# Validate certificate chain
ssl-toolkit cert verify --chain chain.pem --hostname example.com

# Convert between PEM, DER, and PKCS#12
ssl-toolkit cert convert cert.pem --to der
ssl-toolkit cert convert cert.pem --to der -o cert.der
ssl-toolkit cert convert --to p12 --cert c.pem --key k.pem
ssl-toolkit cert convert bundle.p12 --to pem --password pass
```

### Non-Interactive Mode

```bash
# Basic check
ssl-toolkit -d example.com --non-interactive

# JSON output
ssl-toolkit -d example.com --json

# Quiet mode (grade only)
ssl-toolkit -d example.com --quiet

# Generate HTML report
ssl-toolkit -d example.com --non-interactive -o report.html

# Override IP address (bypass DNS)
ssl-toolkit -d example.com -i 192.168.1.100 --non-interactive

# Custom port
ssl-toolkit -d example.com -p 8443 --non-interactive

# Skip WHOIS lookup
ssl-toolkit -d example.com --non-interactive --skip-whois
```

### Exit Codes

- `0` - All checks passed
- `1` - Warning (e.g., certificate expiring soon)
- `2` - Failure (e.g., certificate expired, connection failed)

## CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--domain` | `-d` | Domain name to check |
| `--ip` | `-i` | Override IP address (bypass DNS) |
| `--port` | `-p` | Port to connect to (default: 443 if not specified) |
| `--non-interactive` | | Skip interactive prompts, auto-select first IP |
| `--json` | | Output results as JSON (implies non-interactive) |
| `--quiet` | `-q` | Minimal output - just the grade |
| `--output` | `-o` | Output HTML report to path |
| `--verbose` | `-v` | Show detailed check information |
| `--skip-whois` | | Skip WHOIS lookup |
| `--timeout` | | Connection timeout in seconds (default: 10) |
| `--config` | | Custom configuration file path |

## Configuration

Configuration files are located in the `config/` directory:

- `default.toml` - DNS providers, SSL settings, timeouts
- `theme.toml` - Icons, colors (Tokyo Night Storm palette), box characters
- `messages.toml` - User-facing text templates

## Pager Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `↑` / `k` | Scroll up |
| `↓` / `j` / `Enter` | Scroll down |
| `Space` / `PageDown` | Page down |
| `b` / `PageUp` | Page up |
| `g` / `Home` | Go to start |
| `G` / `End` | Go to end |
| `s` | Save report (opens file explorer prompt with tab-completion) |
| `n` | New check (clears screen, returns to menu or re-launches) |
| `q` / `Esc` | Quit pager |

## Reports

SSL-Toolkit generates self-contained HTML reports that include:

- Certificate status and validity period
- Connection details (protocol, cipher suite)
- Certificate chain visualization
- Subject Alternative Names (SANs)
- Downloadable PEM certificate
- iCal expiry reminder

## Architecture

```
src/
├── main.rs              # Entry point, interactive menu loop, CLI dispatch
├── lib.rs               # Public API exports
├── runner.rs            # Check orchestration engine
├── cli/                 # Clap argument definitions (+ SubCommand, CertAction)
├── cert_ops/            # Certificate file operations
│   ├── reader.rs        # Format detection & certificate reading (PEM/DER/PKCS#12)
│   ├── key_match.rs     # Private key parsing & cert/key pair matching
│   ├── chain_verify.rs  # Certificate chain integrity validation
│   ├── convert.rs       # Format conversion (PEM↔DER↔PKCS#12)
│   └── runner.rs        # CLI + interactive runners (pager display)
├── config/              # Configuration loading (settings, theme, messages)
├── checks/              # Core diagnostic modules
│   ├── dns.rs           # Multi-provider DNS resolution
│   ├── tcp.rs           # Port connectivity tests
│   ├── ssl.rs           # TLS protocol & cipher checks
│   ├── certificate.rs   # Certificate parsing
│   └── whois.rs         # WHOIS lookups
├── models/              # Data structures
│   └── cert_comparison.rs # Cross-IP certificate comparison
├── output/              # CLI output formatting
│   ├── banner.rs        # ASCII art banner, screen clear, refresh helpers
│   ├── interactive.rs   # Inquire prompts, Tokyo Night theme, file path autocomplete
│   ├── results.rs       # Formatted result display
│   ├── tables.rs        # Table formatting (comfy-table)
│   ├── grade.rs         # Grade display (A+ through F)
│   ├── cert_chain.rs    # Certificate chain visualization
│   ├── json.rs          # JSON output mode
│   └── pager.rs         # Ratatui scrollable viewer (Tokyo Night themed)
├── report/              # HTML, iCal, PEM generation
└── utils/               # Progress indicators, error types
```

## Dependencies

Key dependencies:
- `clap` - CLI parsing
- `tokio` - Async runtime
- `ratatui` + `crossterm` - Pager view (scrollable results)
- `inquire` + `console` - Interactive CLI prompts (Tokyo Night themed, file path autocomplete)
- `comfy-table` - Table formatting
- `hickory-resolver` - DNS resolution
- `rustls` - Modern TLS (1.2/1.3)
- `native-tls` - Legacy protocol detection
- `x509-parser` - Certificate parsing
- `whois-rust` - WHOIS lookups
- `serde_json` - JSON output
- `minijinja` - HTML templating
- `icalendar` - Calendar generation
- `indicatif` - Progress indicators
- `ansi-to-tui` - ANSI text rendering in pager

## Testing

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Test against specific domains
cargo run -- -d badssl.com --non-interactive
cargo run -- -d expired.badssl.com --non-interactive
cargo run -- -d self-signed.badssl.com --non-interactive
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
