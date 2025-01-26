# SSL Certificate Checker 🔒

A Python tool for checking SSL certificates, certificate chains, and DNS information for domains.

## Features

- 🔒 SSL Certificate validation
- 🔗 Full certificate chain analysis
- ⚠️ Trust status verification
- 📅 Expiration checking
- 🚫 Revocation checking
- 📌 HPKP (HTTP Public Key Pinning) checking
- 🌐 DNS record lookup
- 🗺️ IP geolocation information

## Installation

1. Clone the repository:
```bash
git clone git@github.com:russmckendrick/ssl-toolkit.git
cd ssl-toolkit
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

You can run the script in two ways:

1. With a domain argument:
```bash
python ssl_checker.py example.com
```

2. Interactive mode:
```bash
python ssl_checker.py
```

The script accepts various input formats and will automatically clean the domain:

```bash
# All these formats work:
python ssl_checker.py www.example.com
python ssl_checker.py https://www.example.com
python ssl_checker.py http://www.example.com/path/to/page
python ssl_checker.py www.example.com:443
python ssl_checker.py https://www.example.com/blog/post?id=123
```

The script will extract just the domain name from any URL format. For example:
- `https://www.russ.cloud/2025/01/12/personal-project-updates-and-ai-editors/` → `www.russ.cloud`
- `https://example.com:443/path?query=123` → `example.com`
- `http://subdomain.example.com/` → `subdomain.example.com`

## Example Output

```
=== 🔒 SSL Certificate Information ===
🏢 Issuer: Let's Encrypt Authority X3
📅 Valid From: 2024-01-01 00:00:00 UTC
📅 Valid Until: 2024-03-31 23:59:59 UTC
✅ Certificate Status: Valid
🚫 Trust Status: Certificate has been revoked

=== 🔗 Certificate Chain ===
...
```

## Certificate Status Types

The tool checks for various certificate issues:

- ✅ Valid and trusted
- 🚫 Revoked certificates
- ⚠️ Untrusted root certificates
- 📛 Expired certificates
- ❌ Invalid certificates

## Features in Detail

### SSL Certificate Validation
- Checks certificate validity
- Verifies trust chain
- Checks for certificate revocation
- Identifies expired certificates
- Detects self-signed certificates
- Shows certificate chain details
