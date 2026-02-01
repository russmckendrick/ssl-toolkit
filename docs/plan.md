# SSL-Toolkit: Overview & Implementation Plan

> **Note:** This is a **historical planning document** from the initial design phase. The actual implementation has evolved significantly from this plan. For the current architecture and features, see [architecture.md](architecture.md).

## Executive Summary

This is a comprehensive SSL/TLS diagnostic tool built in Rust that combines interactive CLI prompts with a ratatui-based pager for output. The tool guides users through domain validation, DNS resolution across multiple providers, and thorough SSL certificate analysis—culminating in exportable HTML reports with embedded assets.

---

## Architecture Overview

```
ssl-toolkit/
├── Cargo.toml
├── CLAUDE.md                     # Claude memory
├── config/
│   ├── default.toml              # Main configuration
│   ├── theme.toml                # Colors, icons, box characters
│   └── messages.toml             # All user-facing text templates
├── docs/
│   ├── plan.md                   # This implementation plan
│   ├── architecture.md           # High-level architecture overview
│   ├── checks.md                 # Detailed check module documentation
│   ├── configuration.md          # Configuration file format
│   └── README.md                 # Index for the documentation
├── README.md                     # Project README
├── src/
│   ├── main.rs                   # Entry point & CLI parsing
│   ├── lib.rs                    # Public API exports
│   ├── config/
│   │   ├── mod.rs                # Configuration loading & types
│   │   ├── theme.rs              # Theme loading & types
│   │   └── messages.rs           # Message template loading
│   ├── tui/
│   │   ├── mod.rs
│   │   ├── app.rs                # TUI application state
│   │   ├── ui.rs                 # UI rendering
│   │   ├── widgets/              # Custom widgets
│   │   └── theme.rs              # Runtime theme application
│   ├── cli/
│   │   ├── mod.rs
│   │   └── args.rs               # Clap argument definitions
│   ├── checks/
│   │   ├── mod.rs
│   │   ├── whois.rs              # WHOIS lookups
│   │   ├── dns.rs                # Multi-provider DNS resolution
│   │   ├── tcp.rs                # Port connectivity tests
│   │   ├── ssl.rs                # SSL/TLS protocol & cipher checks
│   │   └── certificate.rs        # Certificate parsing & validation
│   ├── report/
│   │   ├── mod.rs
│   │   ├── html.rs               # HTML report generation
│   │   ├── ical.rs               # iCal generation
│   │   └── pem.rs                # PEM export utilities
│   ├── models/
│   │   ├── mod.rs
│   │   ├── domain.rs             # Domain validation types
│   │   ├── dns_result.rs         # DNS lookup results
│   │   ├── ssl_result.rs         # SSL check results
│   │   ├── test_result.rs        # Verbose result structures
│   │   └── report_card.rs        # Aggregated results
│   └── utils/
│       ├── mod.rs
│       ├── progress.rs           # Progress indicators
│       └── error.rs              # Error types
├── templates/
│   └── report.html               # HTML report template
├── assets/
│   ├── logo.svg                  # SVG logo for HTML/PDF reports
│   └── logo.txt                  # ANSI art for terminal
└── tests/
    ├── integration/
    └── unit/
```

### Assets

- **`assets/logo.svg`** - Vector logo featuring a shield with padlock motif, used in HTML/PDF reports
- **`assets/logo.txt`** - ANSI art version for terminal display

---

## Implementation Phases

### Phase 1: Foundation (Week 1)

**Objective:** Establish project structure, configuration system, and CLI framework.

#### Tasks

| Task | Description | Crates |
|------|-------------|--------|
| 1.1 | Project scaffolding with workspace structure | — |
| 1.2 | CLI argument parsing with full option support | `clap` (derive) |
| 1.3 | Configuration system with defaults + file override | `config`, `serde` |
| 1.4 | Error handling foundation | `thiserror`, `anyhow` |
| 1.5 | Logging infrastructure | `tracing`, `tracing-subscriber` |

#### CLI Arguments Design

```rust
#[derive(Parser)]
#[command(name = "ssl-toolkit", version, about)]
struct Cli {
    /// Domain to check
    #[arg(short, long)]
    domain: Option<String>,
    
    /// Override IP address (bypass DNS)
    #[arg(short, long)]
    ip: Option<IpAddr>,
    
    /// Custom port (default: 443)
    #[arg(short, long, default_value = "443")]
    port: u16,
    
    /// Skip TUI, run inline
    #[arg(long)]
    no_gui: bool,
    
    /// Output HTML report path
    #[arg(short, long)]
    output: Option<PathBuf>,
}
```

#### Configuration Schema (config/default.toml)

```toml
[dns_providers]
local = { name = "Local DNS", address = "system" }
google = { name = "Google DNS", address = "8.8.8.8" }
cloudflare = { name = "Cloudflare", address = "1.1.1.1" }
opendns = { name = "OpenDNS", address = "208.67.222.222" }

[ssl]
default_port = 443
timeout_seconds = 10
```

#### Theme Configuration (config/theme.toml)

```toml
[icons]
pass = "✓"
fail = "✗"
warning = "⚠"
info = "ℹ"
critical = "⛔"
section_start = "══"
subsection = "──"
cert_leaf = "📄"
cert_intermediate = "📄"
cert_root = "🔐"
spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

[box_chars]
top_left = "┌"
top_right = "┐"
bottom_left = "└"
bottom_right = "┘"
horizontal = "─"
vertical = "│"
t_down = "┬"
t_up = "┴"
t_right = "├"
t_left = "┤"
cross = "┼"

[box_chars_double]
top_left = "╔"
top_right = "╗"
bottom_left = "╚"
bottom_right = "╝"
horizontal = "═"
vertical = "║"

[colors]
pass = "#10B981"
fail = "#EF4444"
warning = "#F59E0B"
info = "#3B82F6"
muted = "#6B7280"
primary = "#7C3AED"
heading = "#F9FAFB"
```

---

### Phase 2: Core Checks Engine (Week 2)

**Objective:** Implement all diagnostic checks as standalone, testable modules.

#### Tasks

| Task | Description | Crates |
|------|-------------|--------|
| 2.1 | Domain validation & parsing | `addr`, `idna` |
| 2.2 | WHOIS lookup implementation | `whois-rust` or raw TCP |
| 2.3 | Multi-provider DNS resolution | `hickory-resolver` |
| 2.4 | TCP port connectivity check | `tokio` (async) |
| 2.5 | SSL/TLS handshake & protocol detection | `rustls`, `native-tls` |
| 2.6 | Certificate chain retrieval & parsing | `x509-parser`, `webpki` |
| 2.7 | Cipher suite enumeration | Custom handshake probing |

#### DNS Check Module

```rust
pub struct DnsChecker {
    providers: Vec<DnsProvider>,
}

pub struct DnsResult {
    pub provider: String,
    pub addresses: Vec<IpAddr>,
    pub query_time: Duration,
    pub error: Option<String>,
}

impl DnsChecker {
    pub async fn resolve_all(&self, domain: &str) -> Vec<DnsResult>;
}
```

#### SSL Check Module

```rust
pub struct SslChecker {
    timeout: Duration,
}

pub struct SslResult {
    pub ip: IpAddr,
    pub port: u16,
    pub tcp_open: bool,
    pub protocols: Vec<ProtocolSupport>,
    pub cipher_suites: Vec<CipherSuite>,
    pub certificate: Option<CertificateInfo>,
    pub chain: Vec<CertificateInfo>,
    pub chain_valid: bool,
    pub hostname_valid: bool,
    pub date_valid: bool,
    pub trust_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

pub struct ProtocolSupport {
    pub protocol: TlsProtocol,
    pub enabled: bool,
    pub ciphers: Vec<String>,
}

pub enum TlsProtocol {
    Ssl3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}
```

---

### Phase 3: TUI Implementation (Week 3)

**Objective:** Build the interactive terminal interface with guided workflow.

#### Tasks

| Task | Description | Crates |
|------|-------------|--------|
| 3.1 | TUI application framework | `ratatui`, `crossterm` |
| 3.2 | Question flow state machine | — |
| 3.3 | Real-time progress display | — |
| 3.4 | Results presentation with report card | — |
| 3.5 | Input validation & error display | — |

#### TUI State Machine

```rust
pub enum AppState {
    Welcome,
    DomainInput { domain: String, cursor: usize },
    DomainValidating,
    DnsResults { results: Vec<DnsResult> },
    IpOverride { use_custom: bool, custom_ip: String },
    PortSelection { port: u16 },
    Running { current_check: String, progress: f32 },
    Results { report: ReportCard },
    SavePrompt { path: String },
    Complete,
}

pub enum Message {
    Input(KeyEvent),
    CheckComplete(CheckType, Result<(), Error>),
    Tick,
}
```

---

## TUI Design Specification

### ⚠️ CRITICAL: Border Alignment Requirements

**All TUI borders, boxes, and table elements MUST be correctly aligned.** This is essential for a professional appearance.

#### Alignment Rules

1. **Fixed-width rendering** - All box drawing must account for Unicode character widths
2. **Consistent padding** - Use exactly 2 spaces inside box edges
3. **Column alignment** - Table columns must align using calculated widths, not assumptions
4. **Nested box alignment** - Inner boxes must be inset by exactly 3 characters from outer boxes
5. **Terminal width awareness** - Calculate available width dynamically; never assume 80 columns
6. **Test on multiple terminals** - Verify alignment in iTerm2, Terminal.app, Windows Terminal, and common Linux terminals

#### Implementation Approach

```rust
/// Calculate display width accounting for Unicode
fn display_width(s: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(s)
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

/// Draw a box with correct alignment
fn draw_box(content: &[String], width: usize) -> Vec<String> {
    let inner_width = width - 4; // Account for "│ " and " │"
    let mut lines = Vec::new();
    
    // Top border
    lines.push(format!("┌{}┐", "─".repeat(width - 2)));
    
    // Content lines
    for line in content {
        let padded = pad_to_width(line, inner_width);
        lines.push(format!("│ {} │", padded));
    }
    
    // Bottom border
    lines.push(format!("└{}┘", "─".repeat(width - 2)));
    
    lines
}
```

#### Required Crate

```toml
[dependencies]
unicode-width = "0.1"
```

---

### Verbose Results Layout (Microsoft Connectivity Analyzer Style)

The results display mirrors the verbose, informative style of the Microsoft Connectivity Analyzer—providing clear pass/fail indicators, descriptive summaries, and expandable "Additional Details" sections.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  🔒 SSL Toolkit v1.0.0                                      www.russ.cloud   │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ════════════════════════════════════════════════════════════════════════    │
│   DNS RESOLUTION                                                             │
│  ════════════════════════════════════════════════════════════════════════    │
│                                                                              │
│  ┌─ Attempting to resolve the hostname www.russ.cloud in DNS ─────────────┐  │
│  │                                                                        │  │
│  │  ✓ The hostname resolved successfully.                                 │  │
│  │                                                                        │  │
│  │  ┌─ Additional Details ─────────────────────────────────────────────┐  │  │
│  │  │                                                                  │  │  │
│  │  │  Provider        Status    IP Addresses              Time       │  │  │
│  │  │  ─────────────────────────────────────────────────────────────  │  │  │
│  │  │  Local DNS       ✓ OK      104.21.67.197             12ms       │  │  │
│  │  │                            172.67.154.112                       │  │  │
│  │  │  Google DNS      ✓ OK      104.21.67.197             24ms       │  │  │
│  │  │                            172.67.154.112                       │  │  │
│  │  │  Cloudflare      ✓ OK      104.21.67.197             18ms       │  │  │
│  │  │                            172.67.154.112                       │  │  │
│  │  │  OpenDNS         ✓ OK      104.21.67.197             31ms       │  │  │
│  │  │                            172.67.154.112                       │  │  │
│  │  │                                                                  │  │  │
│  │  │  Unique addresses discovered: 2                                  │  │  │
│  │  │  DNS consistency: All providers returned matching results        │  │  │
│  │  │                                                                  │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌─ Performing WHOIS lookup for russ.cloud ───────────────────────────────┐  │
│  │                                                                        │  │
│  │  ✓ WHOIS information retrieved successfully.                          │  │
│  │                                                                        │  │
│  │  ┌─ Additional Details ─────────────────────────────────────────────┐  │  │
│  │  │  Registrar:       Cloudflare, Inc.                               │  │  │
│  │  │  Created:         2019-03-15                                     │  │  │
│  │  │  Expires:         2026-03-15                                     │  │  │
│  │  │  Name Servers:    clark.ns.cloudflare.com                        │  │  │
│  │  │                   diana.ns.cloudflare.com                        │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ════════════════════════════════════════════════════════════════════════    │
│   SSL/TLS CHECK: 104.21.67.197:443                                          │
│  ════════════════════════════════════════════════════════════════════════    │
│                                                                              │
│  ┌─ Testing TCP port 443 on host 104.21.67.197 ───────────────────────────┐  │
│  │                                                                        │  │
│  │  ✓ The port is open and accepting connections.                        │  │
│  │                                                                        │  │
│  │  ┌─ Additional Details ─────────────────────────────────────────────┐  │  │
│  │  │  Connection time:     45ms                                       │  │  │
│  │  │  Socket state:        ESTABLISHED                                │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌─ Probing SSL/TLS protocols and cipher suites ──────────────────────────┐  │
│  │                                                                        │  │
│  │  ✓ Protocol and cipher suite detection completed successfully.        │  │
│  │                                                                        │  │
│  │  ┌─ Additional Details ─────────────────────────────────────────────┐  │  │
│  │  │                                                                  │  │  │
│  │  │  Protocol      Status          Cipher Suites                    │  │  │
│  │  │  ───────────────────────────────────────────────────────────    │  │  │
│  │  │  SSL 3.0       ✗ Not enabled   —                                │  │  │
│  │  │  TLS 1.0       ✗ Not enabled   —                                │  │  │
│  │  │  TLS 1.1       ✗ Not enabled   —                                │  │  │
│  │  │  TLS 1.2       ✓ Enabled       18 cipher suites                 │  │  │
│  │  │  TLS 1.3       ✓ Enabled       3 cipher suites                  │  │  │
│  │  │                                                                  │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                        │  │
│  │  ┌─ TLS 1.2 Cipher Suites ──────────────────────────────────────────┐  │  │
│  │  │  • TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256                       │  │  │
│  │  │  • TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256                 │  │  │
│  │  │  • TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384                       │  │  │
│  │  │  • TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256                         │  │  │
│  │  │  • TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256                   │  │  │
│  │  │    ... and 13 more (press [E] to expand)                         │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                        │  │
│  │  ┌─ TLS 1.3 Cipher Suites ──────────────────────────────────────────┐  │  │
│  │  │  • TLS_AES_128_GCM_SHA256                                        │  │  │
│  │  │  • TLS_AES_256_GCM_SHA384                                        │  │  │
│  │  │  • TLS_CHACHA20_POLY1305_SHA256                                  │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌─ Checking modern TLS compatibility ────────────────────────────────────┐  │
│  │                                                                        │  │
│  │  ✓ Server supports modern TLS protocols and cipher suites.            │  │
│  │                                                                        │  │
│  │  ┌─ Additional Details ─────────────────────────────────────────────┐  │  │
│  │  │  The server configuration meets current security best practices. │  │  │
│  │  │  • Deprecated protocols (SSL 3.0, TLS 1.0, TLS 1.1) disabled     │  │  │
│  │  │  • TLS 1.2 enabled with strong cipher suites                     │  │  │
│  │  │  • TLS 1.3 enabled (recommended)                                 │  │  │
│  │  │  • Forward secrecy supported (ECDHE key exchange)                │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ════════════════════════════════════════════════════════════════════════    │
│   CERTIFICATE VALIDATION                                                     │
│  ════════════════════════════════════════════════════════════════════════    │
│                                                                              │
│  ┌─ Obtaining SSL certificate from www.russ.cloud:443 ────────────────────┐  │
│  │                                                                        │  │
│  │  ✓ SSL certificate obtained successfully.                             │  │
│  │                                                                        │  │
│  │  ┌─ Certificate Information ────────────────────────────────────────┐  │  │
│  │  │  Subject:        CN=russ.cloud                                   │  │  │
│  │  │  Issuer:         CN=WE1, O=Google Trust Services, C=US           │  │  │
│  │  │  Serial:         04:9A:2B:3C:4D:5E:6F:70:81:92:A3:B4             │  │  │
│  │  │  Thumbprint:     31AF72322977019A2BD39070D0E2BD0129693ADB        │  │  │
│  │  │  Valid From:     2025-11-30 15:13:55 UTC                         │  │  │
│  │  │  Valid Until:    2026-02-28 16:13:52 UTC                         │  │  │
│  │  │  Key Type:       ECDSA P-256                                     │  │  │
│  │  │  Signature:      SHA256withECDSA                                 │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌─ Validating certificate hostname ──────────────────────────────────────┐  │
│  │                                                                        │  │
│  │  ✓ The certificate hostname was validated successfully.               │  │
│  │                                                                        │  │
│  │  ┌─ Additional Details ─────────────────────────────────────────────┐  │  │
│  │  │  Requested hostname: www.russ.cloud                              │  │  │
│  │  │  Match type:         Subject Alternative Name (SAN)              │  │  │
│  │  │                                                                  │  │  │
│  │  │  Subject Alternative Names in certificate:                       │  │  │
│  │  │    • DNS: russ.cloud                                             │  │  │
│  │  │    • DNS: *.russ.cloud                                           │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌─ Building and validating certificate chain ────────────────────────────┐  │
│  │                                                                        │  │
│  │  ✓ Certificate chain is complete and trusted.                         │  │
│  │                                                                        │  │
│  │  ┌─ Test Steps ─────────────────────────────────────────────────────┐  │  │
│  │  │                                                                  │  │  │
│  │  │  ✓ Attempting to build certificate chains for CN=russ.cloud     │  │  │
│  │  │    Result: 1 valid chain constructed successfully.               │  │  │
│  │  │                                                                  │  │  │
│  │  │  ✓ Analyzing chain for compatibility problems                    │  │  │
│  │  │    Result: No compatibility issues identified.                   │  │  │
│  │  │                                                                  │  │  │
│  │  │  ✓ Verifying chain terminates at trusted root                    │  │  │
│  │  │    Result: Chain validated to trusted root CA.                   │  │  │
│  │  │                                                                  │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                        │  │
│  │  ┌─ Certificate Chain ──────────────────────────────────────────────┐  │  │
│  │  │                                                                  │  │  │
│  │  │   ┌─────────────────────────────────────────────────────────┐   │  │  │
│  │  │   │ 📄 Leaf Certificate                                      │   │  │  │
│  │  │   │    CN=russ.cloud                                         │   │  │  │
│  │  │   │    Expires: 2026-02-28 (89 days remaining)               │   │  │  │
│  │  │   └─────────────────────────────────────────────────────────┘   │  │  │
│  │  │                          │                                      │  │  │
│  │  │                          ▼                                      │  │  │
│  │  │   ┌─────────────────────────────────────────────────────────┐   │  │  │
│  │  │   │ 📄 Intermediate Certificate                              │   │  │  │
│  │  │   │    CN=WE1, O=Google Trust Services, C=US                 │   │  │  │
│  │  │   │    Expires: 2027-12-15                                   │   │  │  │
│  │  │   └─────────────────────────────────────────────────────────┘   │  │  │
│  │  │                          │                                      │  │  │
│  │  │                          ▼                                      │  │  │
│  │  │   ┌─────────────────────────────────────────────────────────┐   │  │  │
│  │  │   │ 🔐 Root Certificate (Trusted)                            │   │  │  │
│  │  │   │    CN=GlobalSign Root CA                                 │   │  │  │
│  │  │   │    OU=Root CA, O=GlobalSign nv-sa, C=BE                  │   │  │  │
│  │  │   │    Expires: 2029-01-28                                   │   │  │  │
│  │  │   └─────────────────────────────────────────────────────────┘   │  │  │
│  │  │                                                                  │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌─ Testing certificate validity dates ───────────────────────────────────┐  │
│  │                                                                        │  │
│  │  ✓ Date validation passed. The certificate is currently valid.        │  │
│  │                                                                        │  │
│  │  ┌─ Additional Details ─────────────────────────────────────────────┐  │  │
│  │  │  Not Valid Before:    2025-11-30 15:13:55 UTC                    │  │  │
│  │  │  Not Valid After:     2026-02-28 16:13:52 UTC                    │  │  │
│  │  │  Current Time:        2026-01-25 14:30:00 UTC                    │  │  │
│  │  │                                                                  │  │  │
│  │  │  Certificate Age:     56 days                                    │  │  │
│  │  │  Time Remaining:      89 days                                    │  │  │
│  │  │  Total Validity:      90 days                                    │  │  │
│  │  │                                                                  │  │  │
│  │  │  ⚠ Note: Certificate expires in less than 90 days.              │  │  │
│  │  │    Consider renewal planning.                                    │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ════════════════════════════════════════════════════════════════════════    │
│   REPORT CARD                                                                │
│  ════════════════════════════════════════════════════════════════════════    │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                                                                        │  │
│  │                    ╔═══════════════════════════════╗                   │  │
│  │                    ║     OVERALL GRADE: A          ║                   │  │
│  │                    ╚═══════════════════════════════╝                   │  │
│  │                                                                        │  │
│  │   Category                          Status        Score               │  │
│  │   ─────────────────────────────────────────────────────────           │  │
│  │   DNS Resolution                    ✓ Pass        ████████████  100%  │  │
│  │   TCP Connectivity                  ✓ Pass        ████████████  100%  │  │
│  │   Protocol Support                  ✓ Pass        ████████████  100%  │  │
│  │   Certificate Validity              ✓ Pass        ████████████  100%  │  │
│  │   Certificate Chain                 ✓ Pass        ████████████  100%  │  │
│  │   Hostname Verification             ✓ Pass        ████████████  100%  │  │
│  │   Cipher Strength                   ✓ Pass        ██████████░░   90%  │  │
│  │                                                                        │  │
│  │   ┌─ Recommendations ───────────────────────────────────────────────┐  │  │
│  │   │  ℹ Certificate expires in 89 days - plan for renewal           │  │  │
│  │   │  ℹ Consider enabling HSTS header for enhanced security         │  │  │
│  │   └─────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                        │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ════════════════════════════════════════════════════════════════════════    │
│                                                                              │
│   [S] Save HTML Report    [P] Export PEM    [C] Export iCal    [R] Restart   │
│   [↑/↓] Scroll            [E] Expand All    [Q] Quit                         │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

### Failed/Warning State Layouts

```
┌─ Testing TCP port 443 on host 192.168.1.100 ──────────────────────────────┐
│                                                                           │
│  ✗ Connection failed. The port is not responding.                         │
│                                                                           │
│  ┌─ Additional Details ────────────────────────────────────────────────┐  │
│  │  Target:           192.168.1.100:443                                │  │
│  │  Error:            Connection timed out after 10 seconds            │  │
│  │  Possible causes:                                                   │  │
│  │    • Firewall blocking port 443                                     │  │
│  │    • Service not running on target host                             │  │
│  │    • Incorrect IP address                                           │  │
│  │                                                                     │  │
│  │  Troubleshooting steps:                                             │  │
│  │    1. Verify the IP address is correct                              │  │
│  │    2. Check firewall rules on the target host                       │  │
│  │    3. Confirm the SSL/TLS service is running                        │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────┘

┌─ Validating certificate hostname ─────────────────────────────────────────┐
│                                                                           │
│  ⚠ Certificate hostname mismatch detected.                                │
│                                                                           │
│  ┌─ Additional Details ────────────────────────────────────────────────┐  │
│  │  Requested hostname:  mail.russ.cloud                               │  │
│  │  Certificate CN:      russ.cloud                                    │  │
│  │                                                                     │  │
│  │  Subject Alternative Names in certificate:                          │  │
│  │    • DNS: russ.cloud                                                │  │
│  │    • DNS: www.russ.cloud                                            │  │
│  │                                                                     │  │
│  │  ⚠ The hostname 'mail.russ.cloud' was NOT found in the certificate │  │
│  │    subject or SAN entries. Browsers will show security warnings.    │  │
│  │                                                                     │  │
│  │  Recommendation:                                                    │  │
│  │    Request a new certificate that includes 'mail.russ.cloud'        │  │
│  │    in the Subject Alternative Names, or use a wildcard certificate. │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────┘

┌─ Testing certificate validity dates ──────────────────────────────────────┐
│                                                                           │
│  ✗ Date validation FAILED. The certificate has EXPIRED.                   │
│                                                                           │
│  ┌─ Additional Details ────────────────────────────────────────────────┐  │
│  │  Not Valid Before:    2024-11-30 15:13:55 UTC                       │  │
│  │  Not Valid After:     2025-02-28 16:13:52 UTC    ← EXPIRED          │  │
│  │  Current Time:        2026-01-25 14:30:00 UTC                       │  │
│  │                                                                     │  │
│  │  Certificate expired 331 days ago.                                  │  │
│  │                                                                     │  │
│  │  ⛔ CRITICAL: This certificate is no longer valid.                  │  │
│  │     All browsers will reject connections to this server.            │  │
│  │                                                                     │  │
│  │  Immediate action required:                                         │  │
│  │    1. Renew the certificate immediately                             │  │
│  │    2. Install the new certificate on the server                     │  │
│  │    3. Verify the renewal with this tool                             │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────┘
```

---

### Result Data Structures

```rust
/// Status of an individual check
#[derive(Debug, Clone)]
pub enum CheckStatus {
    Pass,
    Warning,
    Fail,
}

/// A single test result with verbose details
#[derive(Debug, Clone)]
pub struct TestResult {
    /// The test being performed (displayed as header)
    pub title: String,
    
    /// Overall status
    pub status: CheckStatus,
    
    /// One-line summary shown immediately after status icon
    pub summary: String,
    
    /// Additional details (key-value pairs or free text)
    pub details: Vec<DetailSection>,
    
    /// Sub-steps for multi-stage tests
    pub test_steps: Vec<TestStep>,
    
    /// Recommendations or troubleshooting tips
    pub recommendations: Vec<String>,
}

/// A section of additional details
#[derive(Debug, Clone)]
pub enum DetailSection {
    /// Key-value pairs displayed in a table
    KeyValue {
        title: Option<String>,
        pairs: Vec<(String, String)>,
    },
    /// Tabular data with headers
    Table {
        title: Option<String>,
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    /// A list of items
    List {
        title: Option<String>,
        items: Vec<String>,
    },
    /// Free-form text
    Text {
        title: Option<String>,
        content: String,
    },
    /// Certificate chain visualisation
    CertificateChain {
        certificates: Vec<CertificateSummary>,
    },
}

/// A step within a multi-step test
#[derive(Debug, Clone)]
pub struct TestStep {
    pub description: String,
    pub status: CheckStatus,
    pub result: String,
}

/// Certificate summary for chain display
#[derive(Debug, Clone)]
pub struct CertificateSummary {
    pub cert_type: CertificateType,
    pub subject: String,
    pub issuer: String,
    pub expires: chrono::DateTime<chrono::Utc>,
    pub days_remaining: i64,
    pub is_trusted: bool,
}

#[derive(Debug, Clone)]
pub enum CertificateType {
    Leaf,
    Intermediate,
    Root,
}
```

---

### Message Templates (config/messages.toml)

```toml
[dns]
title = "Attempting to resolve the hostname {hostname} in DNS"
success = "The hostname resolved successfully."
failure = "DNS resolution failed. The hostname could not be resolved."
partial = "DNS resolution partially succeeded. Some providers failed."

[dns.details]
consistency_match = "DNS consistency: All providers returned matching results"
consistency_mismatch = "DNS consistency: WARNING - Providers returned different results"

[tcp]
title = "Testing TCP port {port} on host {ip} to ensure it's listening and open"
success = "The port is open and accepting connections."
failure = "Connection failed. The port is not responding."
timeout = "Connection timed out after {seconds} seconds."

[tcp.troubleshooting]
firewall = "Firewall blocking port {port}"
service_down = "Service not running on target host"
wrong_ip = "Incorrect IP address"

[protocols]
title = "Probing SSL/TLS protocols and cipher suites on {ip}:{port}"
success = "Protocol and cipher suite detection completed successfully."
failure = "Failed to detect supported protocols and cipher suites."

[protocols.status]
enabled = "Enabled"
not_enabled = "Not enabled"
deprecated = "Enabled (DEPRECATED - security risk)"

[certificate.obtain]
title = "Obtaining SSL certificate from {hostname}:{port}"
success = "SSL certificate obtained successfully."
failure = "Failed to retrieve SSL certificate from server."

[certificate.hostname]
title = "Validating certificate hostname"
success = "The certificate hostname was validated successfully."
mismatch = "Certificate hostname mismatch detected."
details_match = "Host name {hostname} was found in the Certificate Subject Alternative Name entry."
details_mismatch = "The hostname '{hostname}' was NOT found in the certificate subject or SAN entries."

[certificate.chain]
title = "Building and validating certificate chain"
success = "Certificate chain is complete and trusted."
incomplete = "Certificate chain is incomplete. Missing intermediate certificates."
untrusted = "Certificate chain does not terminate at a trusted root."

[certificate.chain.steps]
building = "Attempting to build certificate chains for {subject}"
building_success = "{count} valid chain(s) constructed successfully."
analyzing = "Analyzing chain for compatibility problems"
analyzing_success = "No compatibility issues identified."
analyzing_warning = "Potential compatibility issues found."
verifying = "Verifying chain terminates at trusted root"
verifying_success = "Chain validated to trusted root CA."
verifying_failure = "Chain does NOT terminate at a trusted root."

[certificate.dates]
title = "Testing certificate validity dates"
success = "Date validation passed. The certificate is currently valid."
expired = "Date validation FAILED. The certificate has EXPIRED."
not_yet_valid = "Date validation FAILED. The certificate is not yet valid."
expiring_soon = "Certificate expires in {days} days. Consider renewal planning."

[compatibility]
title = "Checking modern TLS compatibility"
success = "Server supports modern TLS protocols and cipher suites."
warning = "Server configuration has potential compatibility issues."
failure = "Server does NOT meet minimum security requirements."

[compatibility.details]
deprecated_disabled = "Deprecated protocols (SSL 3.0, TLS 1.0, TLS 1.1) disabled"
deprecated_enabled = "WARNING: Deprecated protocols are enabled"
tls12_strong = "TLS 1.2 enabled with strong cipher suites"
tls13_enabled = "TLS 1.3 enabled (recommended)"
forward_secrecy = "Forward secrecy supported (ECDHE key exchange)"
```

---

### Phase 4: Headless Mode (Week 4)

**Objective:** Implement `--no-gui` mode with inline progress updates.

#### Tasks

| Task | Description | Crates |
|------|-------------|--------|
| 4.1 | Inline progress indicator (single-line overwrite) | `indicatif` |
| 4.2 | Auto-flow with CLI arguments | — |
| 4.3 | Non-interactive output formatting | — |
| 4.4 | Exit codes for scripting | — |

#### Inline Progress Example

```
⠸ Checking Cloudflare DNS...
```
Overwrites to:
```
✓ DNS: 4/4 providers resolved (2 unique IPs)
⠸ Testing TCP 104.21.67.197:443...
```

---

### Phase 5: Report Generation (Week 5)

**Objective:** Generate self-contained HTML reports with embedded downloads.

#### Tasks

| Task | Description | Crates |
|------|-------------|--------|
| 5.1 | HTML template system | `minijinja` or `tera` |
| 5.2 | Certificate chain PEM embedding | `base64` |
| 5.3 | iCal generation with reminder events | `icalendar` |
| 5.4 | Base64 data URI encoding for downloads | — |
| 5.5 | Report styling (embedded CSS) | — |

#### iCal Reminder Structure

```rust
pub fn generate_ical(cert: &CertificateInfo) -> String {
    let reminders = [30, 15, 5, 1]; // days before expiry
    
    for days in reminders {
        // VEVENT with:
        // - DTSTART: expiry - days
        // - SUMMARY: "SSL Certificate Expiring: {domain}"
        // - DESCRIPTION: Full cert details
        // - VALARM: At event time
    }
}
```

#### HTML Download Embedding

```html
<a href="data:application/x-pem-file;base64,{base64_pem}" 
   download="certificate-chain.pem">
   Download Certificate Chain (PEM)
</a>

<a href="data:text/calendar;base64,{base64_ical}"
   download="ssl-expiry-reminders.ics">
   Download Calendar Reminders
</a>
```

---

### Phase 6: Testing & Polish (Week 6)

**Objective:** Comprehensive testing, cross-platform validation, and refinement.

#### Tasks

| Task | Description |
|------|-------------|
| 6.1 | Unit tests for all check modules |
| 6.2 | Integration tests with mock servers |
| 6.3 | Cross-platform CI (GitHub Actions: macOS, Linux, Windows) |
| 6.4 | Error message refinement |
| 6.5 | Documentation (README, `--help` text) |
| 6.6 | Release builds & binary distribution |

#### Test Strategy

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    
    #[tokio::test]
    async fn test_dns_resolution_success() {
        // Test against known domains
    }
    
    #[tokio::test]
    async fn test_ssl_check_expired_cert() {
        // Use badssl.com test endpoints
    }
    
    #[tokio::test]
    async fn test_ssl_check_wrong_host() {
        // wrong.host.badssl.com
    }
}
```

---

## Key Dependencies

| Crate | Purpose | Notes |
|-------|---------|-------|
| `clap` | CLI parsing | Derive macros |
| `tokio` | Async runtime | Full features |
| `ratatui` | TUI framework | With crossterm backend |
| `crossterm` | Terminal manipulation | Cross-platform |
| `hickory-resolver` | DNS resolution | Async, multiple providers |
| `rustls` | TLS implementation | Modern, safe |
| `native-tls` | Platform TLS | Fallback for legacy protocols |
| `x509-parser` | Certificate parsing | Full chain support |
| `indicatif` | Progress bars | Headless mode |
| `config` | Configuration | TOML support |
| `minijinja` | Templating | HTML reports |
| `icalendar` | iCal generation | RFC 5545 compliant |
| `chrono` | Date/time handling | Timezone aware |
| `serde` | Serialisation | JSON/TOML |
| `tracing` | Logging | Structured |
| `thiserror` | Error definitions | — |
| `anyhow` | Error propagation | — |
| `unicode-width` | Display width calculation | **Required for TUI alignment** |

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Legacy TLS protocol detection (SSLv3, TLS 1.0/1.1) | Use `native-tls` or raw socket probing as `rustls` doesn't support deprecated protocols |
| WHOIS rate limiting | Implement caching, exponential backoff |
| Cross-platform terminal rendering | Extensive testing on all platforms, `crossterm` handles most differences |
| Large certificate chains | Streaming/chunked processing, memory limits |
| Network timeouts in CI | Mock servers for unit tests, longer timeouts for integration |
| **TUI border misalignment** | Use `unicode-width` crate, test on multiple terminals, implement width-aware rendering functions |

---

## Success Criteria

1. **Functional:** All specified checks complete successfully against test domains
2. **Cross-platform:** Builds and runs on macOS, Linux, Windows without modification
3. **UX:** TUI feels responsive and modern (sub-100ms input latency)
4. **Visual:** All TUI borders and tables render with correct alignment across terminals
5. **Reports:** HTML reports render correctly in major browsers with working downloads
6. **Testing:** >80% code coverage on core check modules
7. **Documentation:** Clear `--help` output and README with examples, detailed documentation with embedded mermaid diagrams in the @docs folder - this should contain a high level overview of the architecture, a detailed breakdown of each check module, and a guide to the configuration file format at least

## Important Notes

- Always use `cargo fmt` to format the code before committing
- Always use `cargo clippy` to check for potential issues before committing
- Always use `cargo test` to run the tests before committing
- Always use `cargo check` to check for potential issues before committing
- Always use `cargo doc --open` to generate the documentation before committing
- Always check and update documentation at every step of the way
- Use existing code as a template for new code and do not duplicate code or functions
