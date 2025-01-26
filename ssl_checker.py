import ssl
import socket
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import dns.resolver
import requests
from typing import Dict, List
import warnings
from cryptography.x509.oid import NameOID
import idna
import sys
from urllib.parse import urlparse

warnings.filterwarnings('ignore', category=DeprecationWarning)

def create_unverified_context():
    """Create an SSL context that doesn't verify certificates."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def get_certificate_info(domain: str) -> Dict:
    """Get SSL certificate information for a domain."""
    context = create_unverified_context()
    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                
                # Process the certificate
                cert_dict = process_certificate(x509_cert)
                
                # Add verification status and check root trust
                try:
                    # Try to verify with default context (without CRL check first)
                    verify_context = ssl.create_default_context()
                    with socket.create_connection((domain, 443)) as verify_sock:
                        with verify_context.wrap_socket(verify_sock, server_hostname=domain) as verify_ssock:
                            cert_dict['verified'] = True
                            cert_dict['trust_status'] = 'trusted'
                            
                            # Now try CRL check separately
                            try:
                                crl_context = ssl.create_default_context()
                                crl_context.verify_flags = ssl.VERIFY_CRL_CHECK_CHAIN
                                with socket.create_connection((domain, 443)) as crl_sock:
                                    with crl_context.wrap_socket(crl_sock, server_hostname=domain) as crl_ssock:
                                        cert_dict['crl_checked'] = True
                            except ssl.SSLError as crl_e:
                                cert_dict['crl_checked'] = False
                                cert_dict['crl_error'] = str(crl_e)
                                if 'certificate revoked' in str(crl_e).lower():
                                    cert_dict['trust_status'] = 'revoked'
                
                except ssl.SSLError as e:
                    cert_dict['verified'] = False
                    cert_dict['verification_error'] = str(e)
                    
                    # Check for specific error types
                    if 'self-signed certificate in certificate chain' in str(e):
                        cert_dict['trust_status'] = 'untrusted_root'
                    elif 'certificate has expired' in str(e):
                        cert_dict['trust_status'] = 'expired'
                    else:
                        cert_dict['trust_status'] = 'invalid'
                
                return cert_dict
    except Exception as e:
        return {'error': str(e)}

def get_certificate_chain(domain: str) -> List[Dict]:
    """Get the full SSL certificate chain for a domain."""
    try:
        hostname_idna = idna.encode(domain).decode('ascii')
        context = create_unverified_context()
        
        with socket.create_connection((hostname_idna, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname_idna) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                
                chain = []
                current_cert = x509_cert
                processed_certs = set()  # Track processed certificates to avoid loops
                
                while True:
                    # Avoid infinite loops by checking if we've seen this cert before
                    cert_id = current_cert.fingerprint(current_cert.signature_hash_algorithm)
                    if cert_id in processed_certs:
                        break
                    processed_certs.add(cert_id)
                    
                    cert_dict = process_certificate(current_cert)
                    chain.append(cert_dict)
                    
                    # Check if this is a self-signed certificate
                    if current_cert.issuer == current_cert.subject:
                        break
                    
                    # Try to get the next certificate in the chain
                    try:
                        got_next = False
                        # Get the AIA extension for the next certificate
                        for extension in current_cert.extensions:
                            if extension.oid == x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                                for access_description in extension.value:
                                    if access_description.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                                        issuer_url = access_description.access_location.value
                                        try:
                                            response = requests.get(issuer_url, timeout=5)
                                            if response.status_code == 200:
                                                next_cert = x509.load_der_x509_certificate(response.content, default_backend())
                                                current_cert = next_cert
                                                got_next = True
                                                break
                                        except (requests.exceptions.RequestException, ValueError) as e:
                                            continue
                                if got_next:
                                    break
                        if not got_next:
                            break
                    except Exception as e:
                        break
                
                return chain
    except Exception as e:
        return [{'error': str(e)}]

def process_certificate(cert: x509.Certificate) -> Dict:
    """Process a certificate and extract relevant information."""
    try:
        # Get certificate version
        version = cert.version.value

        # Get validity dates using UTC methods
        not_before = cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
        not_after = cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')

        # Get signature algorithm
        sig_algorithm = cert.signature_algorithm_oid._name

        # Get serial number
        serial = format(cert.serial_number, 'x')

        # Get subject alternative names
        san = []
        try:
            for ext in cert.extensions:
                if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    san = [name.value for name in ext.value]
        except:
            pass

        # Helper function to process name attributes
        def get_name_attributes(name):
            attrs = {}
            for oid in [NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME, 
                       NameOID.COUNTRY_NAME, NameOID.STATE_OR_PROVINCE_NAME,
                       NameOID.LOCALITY_NAME]:
                try:
                    value = name.get_attributes_for_oid(oid)
                    if value:
                        attrs[oid._name] = value[0].value
                except:
                    continue
            return attrs

        return {
            'version': version,
            'subject': get_name_attributes(cert.subject),
            'issuer': get_name_attributes(cert.issuer),
            'not_before': not_before,
            'not_after': not_after,
            'signature_algorithm': sig_algorithm,
            'serial_number': serial,
            'subject_alt_names': san
        }
    except Exception as e:
        return {'error': str(e)}

def get_dns_info(domain: str) -> Dict:
    """Get DNS resolution information for a domain."""
    try:
        # Get A records (IPv4)
        a_records = [str(ip) for ip in dns.resolver.resolve(domain, 'A')]
        
        # Get AAAA records (IPv6)
        try:
            aaaa_records = [str(ip) for ip in dns.resolver.resolve(domain, 'AAAA')]
        except:
            aaaa_records = []
        
        # Get IP information
        ip_info = []
        for ip in a_records:
            try:
                response = requests.get(f'https://ipwho.is/{ip}').json()
                if response.get('success', False):
                    ip_info.append({
                        'ip': ip,
                        'country': response.get('country'),
                        'city': response.get('city'),
                        'org': response.get('connection', {}).get('org')
                    })
                else:
                    ip_info.append({'ip': ip, 'error': 'Could not fetch IP information'})
            except Exception as e:
                ip_info.append({'ip': ip, 'error': f'Could not fetch IP information: {str(e)}'})
        
        return {
            'a_records': a_records,
            'aaaa_records': aaaa_records,
            'ip_info': ip_info
        }
    except Exception as e:
        return {'error': str(e)}

def check_hpkp(domain: str) -> Dict:
    """Check for HTTP Public Key Pinning."""
    try:
        context = create_unverified_context()
        url = f"https://{domain}"
        
        # Create a session to handle the connection
        session = requests.Session()
        session.verify = False  # Disable SSL verification for the check
        
        # Suppress only the InsecureRequestWarning from urllib3
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
        response = session.get(url)
        headers = response.headers
        
        result = {
            'has_hpkp': False,
            'max_age': None,
            'include_subdomains': False,
            'report_uri': None,
            'pins': []
        }
        
        # Check for HPKP header (both standard and report-only)
        for header in ['Public-Key-Pins', 'Public-Key-Pins-Report-Only']:
            if header in headers:
                result['has_hpkp'] = True
                pin_header = headers[header]
                
                # Parse the header
                parts = [p.strip() for p in pin_header.split(';')]
                for part in parts:
                    if part.startswith('pin-'):
                        pin = part.split('=', 1)[1].strip('"')
                        result['pins'].append(pin)
                    elif part.startswith('max-age='):
                        result['max_age'] = int(part.split('=')[1])
                    elif part == 'includeSubDomains':
                        result['include_subdomains'] = True
                    elif part.startswith('report-uri='):
                        result['report_uri'] = part.split('=', 1)[1].strip('"')
                
                break
        
        return result
    except Exception as e:
        return {'error': str(e)}

def clean_domain(input_domain: str) -> str:
    """Clean and validate domain input."""
    try:
        # Remove any whitespace
        domain = input_domain.strip()
        
        # Check if it's a URL
        if '://' in domain:
            parsed = urlparse(domain)
            domain = parsed.netloc
        else:
            # Remove any protocol prefix if user entered without //
            if domain.startswith('http:'):
                domain = domain[5:]
            elif domain.startswith('https:'):
                domain = domain[6:]
            
            # Remove any paths and query parameters
            domain = domain.split('/')[0]
            domain = domain.split('?')[0]
            domain = domain.split('#')[0]
        
        # Remove any trailing dots
        domain = domain.rstrip('.')
        
        # Basic domain validation
        if not domain or '.' not in domain:
            raise ValueError("Invalid domain format")
        
        # Remove any port numbers if present
        domain = domain.split(':')[0]
        
        # Convert to punycode if needed
        try:
            domain = idna.encode(domain).decode('ascii')
        except:
            pass
        
        return domain
    except Exception as e:
        raise ValueError(f"Invalid domain: {str(e)}")

def main():
    # Get domain from command line argument or prompt
    if len(sys.argv) > 1:
        input_domain = sys.argv[1].strip()
    else:
        input_domain = input("Enter domain name (e.g., example.com): ").strip()
    
    try:
        domain = clean_domain(input_domain)
    except ValueError as e:
        print(f"❌ Error: {str(e)}")
        print("Please enter a valid domain name (e.g., example.com)")
        return
    
    print(f"\nChecking domain: {domain}")
    print("\n=== 🔒 SSL Certificate Information ===")
    cert_info = get_certificate_info(domain)
    if 'error' not in cert_info:
        print(f"🏢 Issuer: {cert_info['issuer'].get('commonName', 'N/A')}")
        print(f"📅 Valid From: {cert_info['not_before']}")
        print(f"📅 Valid Until: {cert_info['not_after']}")
        
        # Add HPKP check before certificate validation
        print("\n=== 📌 HPKP Information ===")
        hpkp_info = check_hpkp(domain)
        if 'error' not in hpkp_info:
            if hpkp_info['has_hpkp']:
                print("✅ HPKP is enabled")
                print(f"⏱️  Max Age: {hpkp_info['max_age']} seconds")
                if hpkp_info['include_subdomains']:
                    print("🔄 Includes Subdomains")
                if hpkp_info['report_uri']:
                    print(f"📝 Report URI: {hpkp_info['report_uri']}")
                print("\n🔐 Pin Values:")
                for pin in hpkp_info['pins']:
                    print(f"  • {pin}")
            else:
                print("❌ HPKP is not enabled")
        else:
            print(f"❌ Error checking HPKP: {hpkp_info['error']}")
        
        print("\n=== 🔒 Certificate Validation ===")
        try:
            valid_until = datetime.datetime.strptime(
                cert_info['not_after'].replace(' UTC', ''), 
                '%Y-%m-%d %H:%M:%S'
            ).replace(tzinfo=datetime.UTC)
            
            is_expired = valid_until <= datetime.datetime.now(datetime.UTC)
            trust_status = cert_info.get('trust_status', 'unknown')
            
            # First check expiration
            if is_expired:
                print("📛 Certificate Status: Expired")
            else:
                # Then check trust status
                if trust_status == 'trusted':
                    print("✅ Certificate Status: Valid and Trusted")
                else:
                    print("❌ Certificate Status: Invalid")
            
            # Show detailed trust status
            if trust_status == 'revoked':
                print("🚫 Trust Status: Certificate has been revoked")
            elif trust_status == 'untrusted_root':
                print("⚠️  Trust Status: Certificate chain contains untrusted root")
            elif trust_status == 'expired':
                print("📛 Trust Status: Certificate has expired")
            elif trust_status == 'trusted':
                print("✅ Trust Status: Certificate chain is trusted")
                if 'crl_checked' in cert_info and not cert_info['crl_checked']:
                    print("⚠️  Note: CRL verification unavailable")
            else:
                print("❌ Trust Status: Certificate validation failed")
            
            if not cert_info.get('verified', True):
                print(f"\n⚠️  Warning: Certificate verification failed")
                print(f"❌ Reason: {cert_info.get('verification_error', 'Unknown')}")
            
            # Exit early only if there are serious issues
            if is_expired or trust_status in ['revoked', 'untrusted_root', 'invalid']:
                print("\n❌ Certificate validation failed. Skipping additional checks.")
                return
            
            # Only continue with chain and DNS if certificate is valid
            print("\n=== 🔗 Certificate Chain ===")
            chain = get_certificate_chain(domain)
            for i, cert in enumerate(chain, 1):
                if 'error' not in cert:
                    print(f"\n📜 Certificate {i}:")
                    print(f"📌 Version: {cert['version']}")
                    print(f"🔑 Serial Number: {cert['serial_number']}")
                    
                    print("\n👤 Subject:")
                    for key, value in cert['subject'].items():
                        print(f"  {key}: {value}")
                    
                    print("\n📝 Issuer:")
                    for key, value in cert['issuer'].items():
                        print(f"  {key}: {value}")
                    
                    print(f"\n⏰ Validity Period:")
                    print(f"  Not Before: {cert['not_before']}")
                    print(f"  Not After: {cert['not_after']}")
                    print(f"\n🔏 Signature Algorithm: {cert['signature_algorithm']}")
                    
                    if cert['subject_alt_names']:
                        print("\n🔄 Subject Alternative Names:")
                        for san in cert['subject_alt_names']:
                            print(f"  {san}")
                else:
                    print(f"❌ Error getting chain: {cert['error']}")
            
            print("\n=== 🌐 DNS Information ===")
            dns_info = get_dns_info(domain)
            if 'error' not in dns_info:
                print("\n📍 IPv4 Addresses:")
                for ip in dns_info['a_records']:
                    print(f"  • {ip}")
                
                if dns_info['aaaa_records']:
                    print("\n📍 IPv6 Addresses:")
                    for ip in dns_info['aaaa_records']:
                        print(f"  • {ip}")
                
                print("\n🌍 IP Information:")
                for ip_data in dns_info['ip_info']:
                    if 'error' not in ip_data:
                        print(f"\n🔍 {ip_data['ip']}:")
                        print(f"  🗺️  Country: {ip_data.get('country', 'N/A')}")
                        print(f"  🏙️  City: {ip_data.get('city', 'N/A')}")
                        print(f"  🏢 Organization: {ip_data.get('org', 'N/A')}")
                    else:
                        print(f"\n❌ {ip_data['ip']}: Error fetching information")
            else:
                print(f"❌ Error getting DNS information: {dns_info['error']}")
                
        except Exception as e:
            print(f"⚠️  Certificate Status: Error parsing date - {str(e)}")
    else:
        print(f"❌ Error getting certificate: {cert_info['error']}")

if __name__ == "__main__":
    main()