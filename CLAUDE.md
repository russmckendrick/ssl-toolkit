# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

```bash
# Build
cargo build                    # Debug build
cargo build --release          # Release build (LTO, stripped)

# Run
cargo run -- example.com       # Check a domain
cargo run -- -i                # Interactive TUI mode
cargo run                      # Launches TUI if in TTY

# Test
cargo test                     # Run all tests

# Code Quality
cargo fmt                      # Format code
cargo clippy -- -D warnings    # Lint with warnings as errors
cargo check                    # Type check without building

# Debug logging
RUST_LOG=debug cargo run -- example.com
```

## Architecture Overview

SSL Toolkit is an async Rust CLI for SSL/TLS certificate analysis, built on tokio with rustls for TLS operations.

### Module Structure

- **`cli/`** - Clap argument parsing (`args.rs`) and interactive session (`interactive.rs`)
- **`certificate/`** - Core SSL logic:
  - `chain.rs` - Certificate chain retrieval via TLS connection, AIA chain completion
  - `info.rs` - Certificate data structures (`CertificateInfo`, `CertificateChain`)
  - `security.rs` - Security grading algorithm (A+ to F scoring)
  - `validation.rs` - OCSP/CRL status checking, trust store validation
- **`dns/`** - DNS resolution using hickory-resolver:
  - `resolver.rs` - Multi-record type resolution (A, AAAA, MX, NS, TXT, CAA, etc.)
  - `tlsa.rs` - DANE/TLSA record generation and validation
- **`commands/`** - Command implementations (check, diff, ct_search, tlsa)
- **`output/`** - Format-specific renderers (terminal, JSON, Markdown, HTML)
- **`tui/`** - Full-screen ratatui dashboard:
  - `app.rs` - Application state, event loop, async task handling
  - `ui.rs` - UI rendering functions
  - `widgets/` - Custom widgets (menu, input, results, grade, status)
- **`ct/`** - Certificate Transparency log queries via crt.sh API
- **`hpkp/`** - HSTS header checking

### Key Patterns

**Async Flow:** Main entry initializes rustls crypto provider, routes to command handlers. Commands use `tokio::spawn` for concurrent operations (batch processing buffers unordered futures).

**Certificate Chain:** `get_certificate_chain()` in `chain.rs` establishes TLS connection, extracts chain, parses with x509-parser. Chain can be completed via AIA (Authority Information Access) URLs.

**Security Grading:** `calculate_security_grade()` in `security.rs` scores certificates on: key size, signature algorithm, validity, chain completeness, OCSP status, CT logging, HSTS, CAA records, expiry proximity.

**TUI Event Loop:** `TuiRunner::run()` polls crossterm events, converts to `KeyAction` (navigation vs input mode), updates `App` state, triggers async checks via mpsc channels.

**Output Abstraction:** Commands accept `OutputFormat` enum, call appropriate renderer. Terminal output uses `console` crate for styling, `tabled` for tables, `indicatif` for progress.

### Error Handling

Custom `SslToolkitError` enum in `error.rs` using thiserror. Variants cover TLS, DNS, certificate parsing, HTTP, and config errors.
