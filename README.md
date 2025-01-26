# SSL Certificate Checker 🔒

A Go tool for checking SSL certificates, certificate chains, and DNS information for domains.

## Features

- 🔒 SSL Certificate validation
- 🔗 Full certificate chain analysis
- ⚠️ Trust status verification
- 📅 Expiration checking
- 🚫 Revocation checking
- 📌 HPKP (HTTP Public Key Pinning) checking
- 🌐 DNS record lookup
- 🗺️ IP geolocation information

## Requirements

- Go 1.21 or higher

## Installation

1. Clone the repository:
```bash
git clone git@github.com:russmckendrick/ssl-toolkit.git
cd ssl-toolkit
```

2. Install dependencies:
```bash
make deps
```

3. Build the application:
```bash
make build
```

## Usage

You can run the application in several ways:

1. Using make:
```bash
make run
```

2. Direct execution after building:
```bash
./build/ssl-checker example.com
```

3. Or build and run in one step:
```bash
go run cmd/ssl-checker/main.go example.com
```

The tool accepts various input formats and will automatically clean the domain:

```bash
# All these formats work:
./build/ssl-checker www.example.com
./build/ssl-checker https://www.example.com
./build/ssl-checker http://www.example.com/path/to/page
./build/ssl-checker www.example.com:443
```

## Development

- Build the application: `make build`
- Run tests: `make test`
- Clean build artifacts: `make clean`

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
