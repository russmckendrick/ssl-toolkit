# SSL Toolkit

A comprehensive SSL/TLS certificate analysis toolkit written in Rust.

## Features

- **Certificate Analysis**
  - SSL/TLS certificate validation
  - Full certificate chain analysis
  - Trust status verification
  - Expiration checking with countdown
  - Security grading (A+ to F)
  - Certificate fingerprints (SHA-256)

- **Security Checks**
  - OCSP status checking
  - Certificate Transparency log search
  - HSTS header detection
  - DANE/TLSA record generation
  - Key size and algorithm analysis

- **DNS Analysis**
  - A, AAAA, MX, NS, TXT, SOA records
  - Nameserver consistency checking
  - CAA record detection
  - SPF, DMARC, BIMI record analysis
  - IP geolocation

- **Output Formats**
  - Rich terminal output with colors and tables
  - JSON export
  - Markdown reports
  - HTML reports

- **Additional Features**
  - Batch processing of multiple domains
  - Watch mode for monitoring certificates
  - Certificate comparison (diff)
  - iCal expiry reminders
  - Interactive mode

## Installation

### From Source (Rust)

1. Ensure you have Rust installed (https://rustup.rs)

2. Clone the repository:
```bash
git clone https://github.com/russmckendrick/ssl-toolkit.git
cd ssl-toolkit
```

3. Build the application:
```bash
cargo build --release
```

4. The binary will be at `target/release/ssl-toolkit`

### Homebrew (macOS)

```bash
brew tap russmckendrick/tap
brew install ssl-toolkit
```

## Usage

### Basic Certificate Check

```bash
# Check a domain
ssl-toolkit example.com

# With verbose output
ssl-toolkit example.com --verbose

# Check at specific IP (useful before DNS changes)
ssl-toolkit example.com --ip 192.168.1.100

# Custom port
ssl-toolkit example.com --port 8443
```

### Output Formats

```bash
# JSON output
ssl-toolkit example.com --format json

# Markdown report
ssl-toolkit example.com --format markdown

# HTML report (saves to file)
ssl-toolkit example.com --format html
```

### Focused Views

```bash
# Show security grade only
ssl-toolkit example.com --grade

# Show certificate chain only
ssl-toolkit example.com --chain

# Show DNS information only
ssl-toolkit example.com --dns
```

### Batch Operations

```bash
# Check multiple domains from file
ssl-toolkit batch domains.txt

# Parallel checking (5 at a time)
ssl-toolkit batch domains.txt --parallel 5

# Only show domains with issues
ssl-toolkit batch domains.txt --issues-only
```

### Watch Mode

```bash
# Monitor certificate (check every 5 minutes)
ssl-toolkit watch example.com --interval 300

# Alert on certificate change
ssl-toolkit watch example.com --alert-on-change

# Alert when expiring within N days
ssl-toolkit watch example.com --alert-expiry-days 30
```

### Certificate Comparison

```bash
# Compare two domains
ssl-toolkit diff example.com other.com

# Compare same domain at different IPs
ssl-toolkit diff example.com --ip 192.168.1.100
```

### Certificate Transparency Search

```bash
# Search CT logs for domain
ssl-toolkit ct-search example.com

# Include expired certificates
ssl-toolkit ct-search example.com --include-expired

# Filter by issuer
ssl-toolkit ct-search example.com --issuer "Let's Encrypt"
```

### TLSA Record Generation

```bash
# Generate DANE/TLSA record
ssl-toolkit tlsa example.com

# Custom parameters
ssl-toolkit tlsa example.com --usage 3 --selector 1 --matching-type 1
```

### Certificate Download & Reminders

```bash
# Download certificate chain as PEM
ssl-toolkit example.com --download-chain

# Create iCal expiry reminder
ssl-toolkit example.com --create-reminder

# Custom reminder days before expiry
ssl-toolkit example.com --create-reminder --reminder-days 14
```

### Interactive Mode

```bash
ssl-toolkit --interactive
```

## Security Grading

The security grade is calculated based on:

| Factor | Max Points | Description |
|--------|------------|-------------|
| Key Size | 20 | RSA 4096+, ECDSA P-384+ = excellent |
| Signature Algorithm | 15 | SHA-256+ required, SHA-1 = fail |
| Certificate Validity | 15 | Valid, trusted certificate |
| Certificate Chain | 10 | Complete chain with trusted root |
| OCSP Status | 10 | Good status, stapling bonus |
| Certificate Transparency | 10 | Logged in CT |
| HSTS | 10 | Strict-Transport-Security header |
| CAA Records | 5 | DNS CAA records configured |
| Expiry Warning | 5 | Days until expiry |

**Grades:**
- **A+**: Score 95-100%
- **A**: Score 85-94%
- **B**: Score 75-84%
- **C**: Score 65-74%
- **D**: Score 50-64%
- **F**: Score below 50% or critical failures

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- example.com
```

### Project Structure

```
src/
├── main.rs           # Entry point
├── cli/              # CLI argument parsing
├── certificate/      # Certificate handling
├── dns/              # DNS resolution
├── ct/               # Certificate Transparency
├── hpkp/             # HSTS checking
├── output/           # Output formatters
├── commands/         # Command implementations
├── utils/            # Utilities
└── error.rs          # Error types
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT License](LICENSE)
