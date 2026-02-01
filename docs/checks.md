# Check Modules

SSL-Toolkit performs several checks in sequence. Each check module is self-contained and follows consistent patterns.

## DNS Resolution (`checks/dns.rs`)

Resolves domain names using multiple DNS providers for comparison.

### Providers

| Provider | Servers | Purpose |
|----------|---------|---------|
| System | System default | Local/ISP resolver |
| Google | 8.8.8.8, 8.8.4.4 | Public DNS |
| Cloudflare | 1.1.1.1, 1.0.0.1 | Fast public DNS |
| OpenDNS | 208.67.222.222, 208.67.220.220 | Security-focused DNS |

### Usage

```rust
let dns_checker = DnsChecker::new(providers);
let results = dns_checker.resolve_all("example.com").await;

for result in results {
    if result.is_success() {
        println!("{}: {:?} ({:.2}ms)",
            result.provider,
            result.addresses,
            result.query_time.as_secs_f64() * 1000.0
        );
    }
}
```

### Result Structure

```rust
pub struct DnsResult {
    pub provider: String,
    pub addresses: Vec<IpAddr>,
    pub query_time: Duration,
    pub error: Option<String>,
}
```

## TCP Connectivity (`checks/tcp.rs`)

Tests TCP connection to a given IP and port.

### Usage

```rust
let tcp_checker = TcpChecker::new(Duration::from_secs(10));
match tcp_checker.check(ip, port).await {
    Ok(duration) => println!("Connected in {:.2}ms", duration.as_secs_f64() * 1000.0),
    Err(e) => println!("Connection failed: {}", e),
}
```

### Error Types

- `ConnectionRefused` - Port is closed
- `ConnectionFailed` - Connection failed (general)
- `Timeout` - Connection timed out
- `HostUnreachable` - Host not reachable
- `NetworkUnreachable` - Network not reachable

## SSL/TLS Analysis (`checks/ssl.rs`)

Performs SSL/TLS handshake and analyzes protocol support.

### Protocol Detection

Uses two TLS libraries:
- **rustls**: Modern TLS 1.2 and TLS 1.3
- **native-tls**: Legacy protocol detection (TLS 1.0, 1.1)

### Usage

```rust
let ssl_checker = SslChecker::new(settings.ssl.clone());
match ssl_checker.check("example.com", ip, 443).await {
    Ok(info) => {
        println!("Protocol: {}", info.protocol);
        println!("Cipher: {}", info.cipher_suite);
        println!("Certificates: {}", info.certificate_chain.len());
    }
    Err(e) => println!("SSL check failed: {}", e),
}
```

### Result Structure

```rust
pub struct SslInfo {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: TlsProtocol,
    pub cipher_suite: String,
    pub supported_protocols: Vec<ProtocolSupport>,
    pub cipher_suites: Vec<CipherSuite>,
    pub certificate_chain: Vec<Vec<u8>>,  // DER encoded
    pub secure_renegotiation: bool,
    pub ocsp_stapling: bool,
    pub trust_verified: bool,
}

pub enum TlsProtocol {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}
```

### Security Evaluation

- **Secure protocols**: TLS 1.2, TLS 1.3
- **Deprecated protocols**: TLS 1.0, TLS 1.1, SSLv3
- **Weak ciphers**: NULL, EXPORT, DES, RC4, MD5

## Certificate Analysis (`checks/certificate.rs`)

Parses and validates X.509 certificates.

### Usage

```rust
let cert_checker = CertificateChecker::new();
match cert_checker.analyze(&ssl_info.certificate_chain) {
    Ok(cert_info) => {
        println!("Subject: {}", cert_info.subject);
        println!("Issuer: {}", cert_info.issuer);
        println!("Valid until: {}", cert_info.not_after);
        println!("Days until expiry: {}", cert_info.days_until_expiry());
    }
    Err(e) => println!("Certificate analysis failed: {}", e),
}
```

### Result Structure

```rust
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub thumbprint: String,  // SHA-256
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub san: Vec<String>,  // Subject Alternative Names
    pub public_key_algorithm: String,
    pub public_key_size: u32,
    pub signature_algorithm: String,
    pub is_self_signed: bool,
    pub is_ca: bool,
    pub version: u32,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub raw_der: Vec<u8>,
}
```

### Validation Checks

- Certificate validity (not expired, not before valid date)
- Hostname matching (CN and SANs)
- Chain validation
- Self-signed detection
- Key strength evaluation

### Chain Parsing

```rust
let chain = cert_checker.parse_chain(&ssl_info.certificate_chain)?;
for cert in chain {
    println!("{}: {} -> {}",
        cert.cert_type,  // Leaf, Intermediate, Root
        cert.subject_cn,
        cert.issuer_cn
    );
}
```

## WHOIS Lookup (`checks/whois.rs`)

Retrieves domain registration information using the `whois-rust` crate with an embedded `servers.json` database from the node-whois project for comprehensive TLD coverage.

### Usage

```rust
let whois_checker = WhoisChecker::default();
match whois_checker.lookup("example.com").await {
    Ok(info) => {
        if let Some(registrar) = info.registrar {
            println!("Registrar: {}", registrar);
        }
        if let Some(expires) = info.expires {
            println!("Expires: {}", expires);
        }
    }
    Err(e) => println!("WHOIS lookup failed: {}", e),
}
```

### Result Structure

```rust
pub struct WhoisInfo {
    pub registrar: Option<String>,
    pub created: Option<String>,
    pub expires: Option<String>,
    pub updated: Option<String>,
    pub nameservers: Vec<String>,
    pub status: Vec<String>,
    pub raw: String,
}
```

### Features

- Comprehensive TLD coverage via embedded node-whois `servers.json`
- Retry with exponential backoff
- Robust parsing for various WHOIS formats (including Nominet `.uk` indented blocks)
- Runs synchronous lookups in `spawn_blocking` to avoid blocking the async runtime

## Check Status

All checks return results that can be converted to a status:

```rust
pub enum CheckStatus {
    Pass,     // Check successful, no issues
    Warning,  // Check successful, but with concerns
    Fail,     // Check failed or critical issue
}
```

### Status Determination

| Check | Pass | Warning | Fail |
|-------|------|---------|------|
| DNS | Resolved to IP | Multiple IPs | No resolution |
| TCP | Connected | - | Connection failed |
| SSL | Modern protocol | Legacy supported | Handshake failed |
| Cert | Valid > 30 days | Valid < 30 days | Expired |
| WHOIS | Data retrieved | No registrar/dates/NS | Lookup failed |

## Running All Checks

The check orchestration is handled by `runner.rs`, which provides an event-driven engine that any frontend can use.

### Runner Configuration

```rust
pub struct RunConfig {
    pub domain: String,
    pub target_ips: Vec<IpAddr>,
    pub port: u16,
    pub settings: Settings,
    pub skip_whois: bool,
}
```

### Running Checks

```rust
use crate::runner::{run_checks, resolve_dns, RunConfig, RunResult, CheckEvent};

// 1. Resolve DNS
let dns_results = resolve_dns(&domain, &settings, &|event| {
    // Handle DNS events (DnsStarted, DnsComplete)
}).await?;

// 2. Run all checks (TCP, SSL, Certificate, WHOIS, Comparison)
let config = RunConfig {
    domain,
    target_ips: selected_ips,
    port: 443,
    settings,
    skip_whois: false,
};

let result: RunResult = run_checks(config, dns_results, &|event| {
    match event {
        CheckEvent::TcpStarted { ip } => { /* ... */ },
        CheckEvent::SslComplete { ip } => { /* ... */ },
        CheckEvent::CertComplete { days } => { /* ... */ },
        CheckEvent::ComparisonStarted { current, total, ip } => { /* ... */ },
        CheckEvent::WhoisComplete => { /* ... */ },
        CheckEvent::Error(msg) => { /* ... */ },
        _ => {}
    }
}).await?;

// 3. Access results
let report = result.report;          // ReportCard with grade
let cert_info = result.cert_info;    // Certificate details
let comparison = result.cert_comparison; // Cross-IP comparison
```

### Run Result

```rust
pub struct RunResult {
    pub report: ReportCard,
    pub ssl_info: Option<SslInfo>,
    pub cert_info: Option<CertificateInfo>,
    pub cert_comparison: CertComparison,
    pub dns_results: Vec<DnsResult>,
}
```
