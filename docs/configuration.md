# Configuration Guide

SSL-Toolkit uses TOML configuration files for customization. All configuration files are located in the `config/` directory.

## Configuration Files

| File | Purpose |
|------|---------|
| `default.toml` | DNS providers, SSL settings, timeouts |
| `theme.toml` | Icons, colors, box characters for CLI output |
| `messages.toml` | User-facing text templates |

## Default Settings (`config/default.toml`)

### DNS Providers

```toml
[[dns_providers]]
name = "System"
servers = []  # Empty = use system resolver
description = "System default DNS resolver"

[[dns_providers]]
name = "Google"
servers = ["8.8.8.8", "8.8.4.4"]
description = "Google Public DNS"

[[dns_providers]]
name = "Cloudflare"
servers = ["1.1.1.1", "1.0.0.1"]
description = "Cloudflare DNS"

[[dns_providers]]
name = "OpenDNS"
servers = ["208.67.222.222", "208.67.220.220"]
description = "Cisco OpenDNS"
```

### SSL Settings

```toml
[ssl]
connect_timeout_secs = 10        # TCP connection timeout
handshake_timeout_secs = 10      # TLS handshake timeout
check_legacy_protocols = true    # Check TLS 1.0, 1.1
check_weak_ciphers = true        # Check for weak ciphers
```

### WHOIS Settings

```toml
[whois]
timeout_secs = 10        # WHOIS query timeout
retry_count = 3          # Number of retries
backoff_base_ms = 1000   # Base for exponential backoff
```

WHOIS server discovery is handled automatically via the embedded node-whois `servers.json` database, which provides comprehensive TLD coverage without manual per-TLD configuration.

## Theme Configuration (`config/theme.toml`)

### Status Icons

```toml
[icons]
pass = "✓"
fail = "✗"
warning = "!"
info = "i"
critical = "X"
cert_leaf = "📄"
cert_intermediate = "⛓"
cert_root = "🔒"
arrow_right = "→"
bullet = "•"
spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
nav_left = "<"
nav_right = ">"
step_complete = "●"
step_current = "⦿"
step_pending = "○"
```

### Box Drawing Characters

```toml
[box_chars]
top_left = "╭"
top_right = "╮"
bottom_left = "╰"
bottom_right = "╯"
horizontal = "─"
vertical = "│"
t_left = "├"
t_right = "┤"
t_top = "┬"
t_bottom = "┴"
cross = "┼"

[double_box]
top_left = "╭"
top_right = "╮"
bottom_left = "╰"
bottom_right = "╯"
horizontal = "═"
vertical = "║"
```

### Colors

All colors are specified in hexadecimal format, using the Tokyo Night Storm palette:

```toml
[colors]
# Tokyo Night Storm Palette
pass = "#9ece6a"        # Green
fail = "#f7768e"        # Red
warning = "#e0af68"     # Orange
info = "#7dcfff"        # Cyan
primary = "#7aa2f7"     # Blue
secondary = "#a9b1d6"   # Foreground / Lavender
background = "#24283b"  # Storm Blue Background
foreground = "#c0caf5"  # Text
border = "#565f89"      # Muted Blue
highlight = "#bb9af7"   # Purple

# Keyboard shortcuts styling
key_background = "#414868"
key_foreground = "#c0caf5"

# Table header styling
table_header_bg = "#414868"

# Grade colors
grade_a = "#9ece6a"
grade_b = "#7aa2f7"
grade_c = "#e0af68"
grade_f = "#f7768e"

# Progress bar colors
bar_filled = "#7aa2f7"
bar_empty = "#414868"

### Visual Elements

```toml
[visual]
bar_filled = "━"
bar_partial = "╸"
bar_empty = "─"
dot_filled = "●"
dot_empty = "○"
badge_left = " "
badge_right = " "
expand_open = "▼"
expand_closed = "▶"
```

## Message Templates (`config/messages.toml`)

### Global Interface

```toml
[header]
app_name = "SSL Toolkit"
separator = " │ "

[header.screen_names]
welcome = "Welcome"
domain_input = "Enter Domain"
dns_results = "DNS Results"
ip_selection = "Select IPs"
port_selection = "Select Port"
running = "Running Checks"
results = "Results"
save_prompt = "Save Report"
complete = "Complete"
error = "Error"

[footer]
nav_separator = " │ "
back_hint = "← Back"
next_hint = "Next →"
```

### Welcome Screen

```toml
[welcome]
title = "SSL Toolkit"
subtitle = "SSL/TLS Certificate Diagnostic Tool"
prompt = "Enter domain to check:"
hint = "Press Enter to continue, Esc to quit"
```

### Check Messages

```toml
[checks]
dns_title = "DNS Resolution"
dns_resolving = "Resolving DNS records..."
dns_success = "DNS resolution successful"
dns_failed = "DNS resolution failed"

whois_title = "WHOIS Lookup"
whois_querying = "Querying WHOIS servers..."

tcp_title = "TCP Connectivity"
tcp_connecting = "Testing TCP connection..."
tcp_success = "TCP connection successful"
tcp_failed = "TCP connection failed"

ssl_title = "SSL/TLS Analysis"
ssl_handshaking = "Performing SSL handshake..."
ssl_success = "SSL handshake successful"
ssl_failed = "SSL handshake failed"

cert_title = "Certificate Analysis"
cert_parsing = "Parsing certificate..."
cert_valid = "Certificate is valid"
cert_expired = "Certificate has expired"
cert_expiring_soon = "Certificate expires within {days} days"
```

### Error Messages

```toml
[errors]
invalid_domain = "Invalid domain name: {domain}"
connection_refused = "Connection refused to {ip}:{port}"
connection_timeout = "Connection timed out to {ip}:{port}"
handshake_failed = "SSL handshake failed: {error}"
no_certificate = "No certificate received from server"
parse_error = "Failed to parse certificate: {error}"
```

### Recommendations

```toml
[recommendations]
upgrade_tls = "Consider upgrading to TLS 1.3 for improved security"
disable_legacy = "Disable legacy protocols (TLS 1.0, TLS 1.1, SSLv3)"
renew_soon = "Certificate expires in {days} days - plan renewal"
renew_urgent = "Certificate expires in {days} days - renew immediately"
fix_chain = "Fix certificate chain - missing intermediate certificates"
use_strong_cipher = "Consider using stronger cipher suites"
```

### Report Messages

```toml
[report]
title = "SSL/TLS Diagnostic Report"
generated = "Generated on {date}"
summary = "Summary"
details = "Detailed Results"
recommendations = "Recommendations"
export_pem = "Export Certificate Chain (PEM)"
export_ical = "Export Expiry Reminder (iCal)"
```

### Navigation Hints

```toml
[hints]
welcome = "Enter: Start │ q: Quit │ ?: Help"
domain_input = "Enter: Submit │ Esc: Back │ ?: Help"
dns_results = "Enter: Continue │ Esc: Back │ ?: Help"
ip_selection = "↑/↓: Navigate │ Space: Toggle │ Tab: Edit Port │ Enter: Continue │ ?: Help"
port_selection = "Enter: Submit │ Esc: Back │ ?: Help"
running = "Please wait..."
results = "↑/↓: Scroll │ Space: Toggle/Expand │ n: New Check │ s: Save │ ?: Help │ q: Quit"
save_prompt = "Enter: Save │ Esc: Cancel"
error = "r: Retry │ q: Quit │ ?: Help"
```

### Help Overlay

```toml
[help]
title = "SSL Toolkit Help"

[[help.sections]]
header = "Navigation"
content = "Use ↑/↓ or j/k to navigate up/down. Use ←/→ or h/l to go back/forward in wizard steps. Press Enter to confirm."

[[help.sections]]
header = "Global Keys"
content = "Press ? or F1 for help, Esc to go back, q to quit the application."

[[help.sections]]
header = "Results View"
content = "Press e to expand/collapse sections, s to save the report, ↑/↓ to scroll."

[[help.sections]]
header = "IP Selection"
content = "Press Space to toggle selection, a to select all, Tab for custom IP input."

[[help.sections]]
header = "Error Recovery"
content = "Press r to retry the last operation, or q to quit."
```

## Template Variables

Messages support placeholder substitution:

| Placeholder | Description |
|-------------|-------------|
| `{domain}` | Domain being checked |
| `{ip}` | IP address |
| `{port}` | Port number |
| `{days}` | Days until expiry |
| `{date}` | Current date |
| `{error}` | Error message |

## Custom Configuration

Use the `--config` CLI option to specify a custom configuration directory:

```bash
ssl-toolkit -d example.com --config /path/to/config/
```

The custom directory should contain:
- `default.toml`
- `theme.toml`
- `messages.toml`

Missing files will use built-in defaults.

## Programmatic Configuration

Configuration can also be set programmatically:

```rust
use ssl_toolkit::config::{Settings, Theme, Messages};

// Load default configuration
let (settings, theme, messages) = load_default_config()?;

// Or with custom path
let (settings, theme, messages) = load_config_from_dir("/path/to/config/")?;

// Access settings
println!("Connect timeout: {}s", settings.ssl.connect_timeout_secs);
println!("Pass color: {}", theme.colors.pass);
println!("Welcome title: {}", messages.welcome.title);
```
