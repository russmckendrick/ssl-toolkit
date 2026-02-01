# SSL-Toolkit Architecture

## Overview

SSL-Toolkit is built using a modular architecture that separates concerns into distinct layers:

```mermaid
flowchart TB
    subgraph Entry["Entry Point"]
        main[main.rs]
    end

    subgraph Runner["Orchestration"]
        runner[runner.rs]
    end

    subgraph Checks["Check Modules"]
        dns[DNS Checker]
        tcp[TCP Checker]
        ssl[SSL Checker]
        cert[Certificate Checker]
        whois[WHOIS Checker]
    end

    subgraph Models["Data Models"]
        dnsResult[DnsResult]
        sslInfo[SslInfo]
        certInfo[CertificateInfo]
        certComp[CertComparison]
        reportCard[ReportCard]
    end

    subgraph Output["Output Module"]
        interactive[Interactive Prompts]
        results[Results Display]
        pager[Pager View]
        json[JSON Output]
        grade[Grade Display]
    end

    subgraph Reports["Report Generation"]
        html[HTML Report]
        pem[PEM Export]
        ical[iCal Export]
    end

    main --> runner
    main --> interactive
    runner --> Checks
    Checks --> Models
    Models --> Output
    Models --> Reports
```

## Module Structure

### Entry Point (`src/main.rs`)

The main entry point handles:
- CLI argument parsing using Clap
- Configuration loading
- Mode selection (interactive CLI, non-interactive, JSON, quiet)
- Top-level error handling

### CLI Module (`src/cli/`)

Defines command-line arguments using Clap derive macros:

```rust
#[derive(Parser)]
pub struct Cli {
    #[arg(short, long)]
    pub domain: Option<String>,

    #[arg(short, long)]
    pub ip: Option<IpAddr>,

    #[arg(short, long)]
    pub port: Option<u16>,

    #[arg(long)]
    pub json: bool,

    #[arg(short, long)]
    pub quiet: bool,

    #[arg(long)]
    pub non_interactive: bool,

    #[arg(short, long)]
    pub output: Option<PathBuf>,

    #[arg(short, long)]
    pub verbose: bool,

    #[arg(long)]
    pub skip_whois: bool,

    #[arg(long, default_value = "10")]
    pub timeout: u64,

    #[arg(long)]
    pub config: Option<PathBuf>,
}
```

### Configuration Module (`src/config/`)

Manages runtime configuration:
- **settings.rs**: DNS providers, SSL timeouts, WHOIS settings
- **theme.rs**: Icons, colors, visual indicators, box characters
- **messages.rs**: User-facing text templates

Configuration is loaded from TOML files with defaults.

### Runner Module (`src/runner.rs`)

The check orchestration engine that extracts check logic into a standalone async engine driven by any frontend.

```rust
pub struct RunConfig {
    pub domain: String,
    pub target_ips: Vec<IpAddr>,
    pub port: u16,
    pub settings: Settings,
    pub skip_whois: bool,
}

pub enum CheckEvent {
    DnsStarted,
    DnsComplete(Vec<DnsResult>),
    TcpStarted { ip: IpAddr },
    TcpComplete { ip: IpAddr, ms: f64 },
    SslStarted { ip: IpAddr },
    SslComplete { ip: IpAddr },
    CertStarted,
    CertComplete { days: i64 },
    ComparisonStarted { current: usize, total: usize, ip: IpAddr },
    ComparisonComplete,
    WhoisStarted,
    WhoisComplete,
    WhoisSkipped,
    Error(String),
}

pub struct RunResult {
    pub report: ReportCard,
    pub ssl_info: Option<SslInfo>,
    pub cert_info: Option<CertificateInfo>,
    pub cert_comparison: CertComparison,
    pub dns_results: Vec<DnsResult>,
}
```

Key functions:
- `resolve_dns()` - DNS resolution across all providers
- `run_checks()` - Runs TCP, SSL, certificate, WHOIS checks and certificate comparison

### Check Modules (`src/checks/`)

```mermaid
classDiagram
    class DnsChecker {
        +providers: Vec~DnsProvider~
        +new(providers) DnsChecker
        +resolve_all(domain) Vec~DnsResult~
    }

    class TcpChecker {
        +timeout: Duration
        +new(timeout) TcpChecker
        +check(ip, port) Result~Duration~
    }

    class SslChecker {
        +settings: SslSettings
        +new(settings) SslChecker
        +check(domain, ip, port) Result~SslInfo~
    }

    class CertificateChecker {
        +new() CertificateChecker
        +analyze(chain) Result~CertificateInfo~
    }

    DnsChecker --> DnsResult
    TcpChecker --> Duration
    SslChecker --> SslInfo
    CertificateChecker --> CertificateInfo
```

Each check module follows a consistent pattern:

```rust
pub struct XxxChecker {
    // Configuration
}

impl XxxChecker {
    pub fn new(...) -> Self { ... }

    pub async fn check(&self, ...) -> Result<XxxInfo, XxxError> {
        // Perform check
    }
}
```

#### DNS Checker
- Uses `hickory-resolver` for async DNS lookups
- Supports multiple providers (System, Google, Cloudflare, OpenDNS)
- Returns `DnsResult` with addresses and timing

#### TCP Checker
- Simple TCP connection test with timeout
- Returns connection duration or error

#### SSL Checker
- Uses `rustls` for modern TLS (1.2, 1.3)
- Uses `native-tls` for legacy protocol detection
- Returns `SslInfo` with protocol, cipher, certificate chain, and `trust_verified`

#### Certificate Checker
- Uses `x509-parser` for certificate parsing
- Extracts subject, issuer, SANs, validity dates
- Validates certificate chain

#### WHOIS Checker
- Uses `whois-rust` with embedded node-whois `servers.json` for TLD server discovery
- Runs synchronous lookups in `spawn_blocking`
- Retries with exponential backoff
- Parses multiple WHOIS response formats (including Nominet `.uk` indented blocks)

### Data Models (`src/models/`)

```mermaid
classDiagram
    class CheckStatus {
        <<enumeration>>
        Pass
        Warning
        Fail
    }

    class Grade {
        <<enumeration>>
        APlus
        A
        AMinus
        BPlus
        B
        BMinus
        CPlus
        C
        CMinus
        D
        F
    }

    class DnsResult {
        +provider: String
        +addresses: Vec~IpAddr~
        +query_time: Duration
        +error: Option~String~
        +is_success() bool
    }

    class SslInfo {
        +ip: IpAddr
        +port: u16
        +protocol: TlsProtocol
        +cipher_suite: String
        +certificate_chain: Vec~Vec~u8~~
        +trust_verified: bool
    }

    class CertificateInfo {
        +subject: String
        +issuer: String
        +not_before: DateTime
        +not_after: DateTime
        +san: Vec~String~
        +days_until_expiry() i64
        +is_expired() bool
    }

    class ReportCard {
        +domain: String
        +ip: String
        +port: u16
        +grade: Grade
        +score: u32
        +dns_result: Option~TestResult~
        +tcp_result: Option~TestResult~
        +ssl_result: Option~TestResult~
        +certificate_result: Option~TestResult~
        +whois_result: Option~TestResult~
        +timestamp: DateTime~Utc~
        +calculate_grade()
    }

    class CertComparison {
        +reference: Option~CertComparisonEntry~
        +entries: Vec~CertComparisonEntry~
        +summary: Option~String~
    }

    class CertComparisonEntry {
        +ip: IpAddr
        +thumbprint: String
        +subject: String
        +issuer: String
        +days_until_expiry: i64
        +serial: String
        +is_different: bool
        +differences: Vec~CertDifference~
        +error: Option~String~
    }

    ReportCard --> Grade
    ReportCard --> CheckStatus
    CertComparison --> CertComparisonEntry
```

### Output Module (`src/output/`)

Handles all CLI output formatting and user interaction:

- **banner.rs**: ASCII art banner display
- **interactive.rs**: Interactive prompts using `dialoguer` (domain input, IP selection, port selection)
- **results.rs**: Formatted check result display with status icons and colored output
- **tables.rs**: Table formatting using `comfy-table`
- **grade.rs**: Visual grade display (A+ through F) with score bars
- **cert_chain.rs**: Certificate chain visualization
- **json.rs**: JSON output mode for scripting
- **pager.rs**: Ratatui-based scrollable viewer for results with status bar

The interactive flow is linear: prompts collect input sequentially, then results are displayed in the pager.

### Report Module (`src/report/`)

```mermaid
flowchart LR
    subgraph Input
        ssl[SslInfo]
        cert[CertificateInfo]
        dns[DnsResults]
        grade[Grade]
    end

    subgraph Generation
        html[HtmlReport]
        pem[PemExporter]
        ical[IcalGenerator]
    end

    subgraph Output
        htmlFile[report.html]
        pemFile[chain.pem]
        icsFile[expiry.ics]
    end

    ssl --> html
    cert --> html
    dns --> html
    grade --> html
    html --> htmlFile

    cert --> pem
    pem --> pemFile

    cert --> ical
    ical --> icsFile
```

Generates output files:
- **html.rs**: Self-contained HTML reports using minijinja
- **pem.rs**: PEM-formatted certificate chain export (excludes leaf)
- **ical.rs**: RFC 5545 compliant calendar reminders

### Utils Module (`src/utils/`)

Common utilities:
- **error.rs**: Custom error types using thiserror
- **progress.rs**: CLI progress indicators using indicatif

## Data Flow

### Interactive Mode Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Prompts as Interactive Prompts
    participant Runner
    participant Checks
    participant Pager

    User->>CLI: ssl-toolkit -d example.com
    CLI->>Prompts: Domain prompt (if not provided)
    CLI->>Runner: resolve_dns(domain)
    Runner->>Checks: DNS resolution
    Checks-->>Runner: Vec<DnsResult>
    Runner-->>CLI: DNS results
    CLI->>Prompts: IP selection prompt
    CLI->>Prompts: Port prompt (if needed)
    CLI->>Runner: run_checks(config, dns_results)
    Runner->>Checks: TCP + SSL + Cert + WHOIS + Comparison
    Checks-->>Runner: RunResult
    Runner-->>CLI: RunResult
    CLI->>Pager: Display results in scrollable pager
    User->>Pager: s (save report)
    Pager-->>User: Report saved
    User->>Pager: q (quit)
```

### Non-Interactive Mode Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Runner
    participant Checks
    participant Report

    User->>CLI: ssl-toolkit -d example.com --non-interactive
    CLI->>Runner: resolve_dns(domain)
    Runner->>Checks: DNS resolution
    Checks-->>Runner: Vec<DnsResult>
    CLI->>Runner: run_checks(config, dns_results)
    Runner->>Checks: TCP + SSL + Cert + WHOIS + Comparison
    Checks-->>Runner: RunResult
    Runner-->>CLI: RunResult
    CLI->>Report: generate (if --output)
    CLI-->>User: Exit code (0=pass, 1=warn, 2=fail)
```

## Error Handling

Uses a hierarchy of domain-specific errors:

```rust
pub enum ToolkitError {
    Dns(DnsError),
    Tcp(TcpError),
    Ssl(SslError),
    Certificate(CertificateError),
    Config(ConfigError),
    Report(ReportError),
    Whois(WhoisError),
    Io(std::io::Error),
}
```

Each error type provides detailed context for debugging.

## Async Architecture

```mermaid
flowchart TB
    subgraph Tokio["Tokio Runtime"]
        main[Main Task]
        dns1[DNS Query 1]
        dns2[DNS Query 2]
        dns3[DNS Query 3]
        dns4[DNS Query 4]
        tcp[TCP Connect]
        tls[TLS Handshake]
    end

    main --> dns1
    main --> dns2
    main --> dns3
    main --> dns4
    dns1 & dns2 & dns3 & dns4 --> tcp
    tcp --> tls
```

Built on Tokio for async I/O:
- DNS queries are concurrent across providers
- TCP connections use async sockets
- TLS handshakes are async with timeout
- WHOIS uses spawn_blocking for sync library

## CI/CD Pipeline

```mermaid
flowchart LR
    subgraph Trigger
        tag["git push tag v*"]
    end

    subgraph Build["Build Job (matrix)"]
        linux["Linux x86_64<br/>ubuntu-latest"]
        macos_amd["macOS x86_64<br/>macos-latest"]
        macos_arm["macOS ARM64<br/>macos-latest"]
        windows["Windows x86_64<br/>windows-latest"]
    end

    subgraph Release["Release Job"]
        collect["Collect artifacts"]
        gh_release["Create GitHub Release"]
    end

    subgraph Tap["Homebrew Tap Update"]
        checksums["Download SHA256"]
        formula["Update formula"]
        push["Push to homebrew-tap"]
    end

    tag --> Build
    linux & macos_amd & macos_arm & windows --> collect
    collect --> gh_release
    gh_release --> Tap
```

### Release Workflow

The release pipeline uses GitHub Actions matrix builds to produce native binaries for each platform. Native compilation is required because `native-tls` links against platform-specific TLS libraries:

| Platform | Runner | TLS Backend | Artifact |
|----------|--------|-------------|----------|
| Linux x86_64 | `ubuntu-latest` | OpenSSL | `ssl-toolkit-linux-amd64` |
| macOS x86_64 | `macos-latest` | Security.framework | `ssl-toolkit-darwin-amd64` |
| macOS ARM64 | `macos-latest` | Security.framework | `ssl-toolkit-darwin-arm64` |
| Windows x86_64 | `windows-latest` | SChannel | `ssl-toolkit-windows-amd64.exe` |

Each build produces a binary and a `.sha256` checksum file. The release job collects all artifacts and creates a GitHub Release via `softprops/action-gh-release`.

### Homebrew Tap

A separate workflow (`.github/workflows/update-tap.yml`) fires on release publication. It downloads macOS checksums and updates the formula in the `homebrew-tap` repository. The artifact naming convention must remain consistent for this integration to work.

## Testing Strategy

1. **Unit Tests**: Each module has inline tests
2. **Integration Tests**: End-to-end tests with wiremock
3. **Test Domains**: Uses badssl.com for edge cases
4. **Manual Testing**: Cross-platform terminal testing
