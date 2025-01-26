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

## Example Output

```
=== 🔒 SSL Certificate Information ===
🏢 Issuer: WE1
📅 Valid From: 2024-12-19 13:25:09 UTC
📅 Valid Until: 2025-03-19 14:25:02 UTC
✅ Certificate Status: Valid and Trusted
✅ Trust Status: Certificate chain is trusted

=== 📌 HPKP Information ===
❌ HPKP is not enabled

=== 🔗 Certificate Chain ===
...
```

## Certificate Status Types

The tool checks for various certificate issues:

- ✅ Valid and Trusted: Certificate is valid and trusted by system roots
- 🚫 Revoked: Certificate has been revoked by the issuer
- ⚠️ Untrusted Root: Certificate chain contains an untrusted root certificate
- 📛 Expired: Certificate has expired
- ❌ Invalid: Certificate failed validation

## Troubleshooting

### Common Issues

1. **Trust Status Shows Invalid but Certificate is Valid**
   - This can happen when the system's root certificate store is outdated
   - Or when intermediate certificates are not properly chained
   - Try updating your system's CA certificates

2. **CRL Verification Unavailable**
   - This is a warning, not an error
   - Indicates that the Certificate Revocation List couldn't be checked
   - Certificate may still be valid and trusted

3. **HPKP Not Enabled**
   - This is informational only
   - Many sites don't use HPKP as it's being deprecated in favor of other security measures

## Development

- Build the application: `make build`
- Run tests: `make test`
- Clean build artifacts: `make clean`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT License](LICENSE)
