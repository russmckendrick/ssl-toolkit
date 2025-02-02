# SSL Certificate Toolkit 🔒

A Go tool for checking SSL certificates, certificate chains, and DNS information for domains.

## Features

- 🔒 SSL Certificate validation
- 🔗 Full certificate chain analysis
- ⚠️ Trust status verification
- 📅 Expiration checking
- 📅 Certificate expiry reminders (iCal format)
- 🚫 Revocation checking
- 📌 HPKP (HTTP Public Key Pinning) checking
- 🌐 DNS record lookup
- 🗺️ IP geolocation information
- 🔍 Pre-DNS certificate checking at specific IP addresses

## Installation

### Homebrew (macOS)

The easiest way to install on macOS is via Homebrew:

```bash
# Add the tap
brew tap russmckendrick/tap

# Install ssl-toolkit
brew install ssl-toolkit
```

### Manual Installation

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
./build/ssl-toolkit example.com
```

3. Or build and run in one step:
```bash
go run cmd/ssl-toolkit/main.go example.com
```

### Additional Commands

#### Download Certificate Chain
```bash
# Save chain to default file (<domain>-chain.pem)
./build/ssl-toolkit example.com --download-chain

# Specify output file
./build/ssl-toolkit example.com --download-chain --output mycerts.pem
```

#### Create Certificate Expiry Reminder
```bash
# Create reminder (saves to <domain>-cert-expiry.ics)
./build/ssl-toolkit example.com --create-reminder

# Specify output file
./build/ssl-toolkit example.com --create-reminder --reminder-file myreminder.ics
```
The reminder will be set for 30 days before the certificate expires and includes:
- Calendar event with expiry details
- Additional 7-day warning alarm
- Description with renewal instructions

#### List Available Root Certificates
```bash
./build/ssl-toolkit --list-certs
```
This command displays all root certificates available in your system's trust store.

The tool accepts various input formats and will automatically clean the domain:

```bash
# All these formats work:
./build/ssl-toolkit www.example.com
./build/ssl-toolkit https://www.example.com
./build/ssl-toolkit http://www.example.com/path/to/page
./build/ssl-toolkit www.example.com:443
```

### Check Certificate at Specific IP

You can check a certificate at a specific IP address before DNS changes:

```bash
# Check certificate for example.com at IP 10.142.4.4
./build/ssl-toolkit example.com --ip 10.142.4.4

# Check in web interface
./build/ssl-toolkit example.com --ip 10.142.4.4 --web
```

This is useful for:
- Verifying certificates before DNS changes
- Testing certificates on load balancers
- Checking certificates on specific servers in a pool

## Example Output

### Basic Certificate Check
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

### List Certificates Output
```
📜 Found 132 Available Root Certificates:

- GlobalSign Root CA
- DigiCert Global Root CA
- Let's Encrypt Root X1
...
```

### Create Reminder Output
```
✅ Certificate expiry reminder saved to example.com-cert-expiry.ics
📅 Reminder set for 30 days before expiry (2025-02-17)
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
