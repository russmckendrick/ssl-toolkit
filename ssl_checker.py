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
                    # Try to verify with default context
                    verify_context = ssl.create_default_context()
                    with socket.create_connection((domain, 443)) as verify_sock:
                        with verify_context.wrap_socket(verify_sock, server_hostname=domain) as verify_ssock:
                            cert_dict['verified'] = True
                            cert_dict['trust_status'] = 'trusted'
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
        
        with socket.create_connection((hostname_idna, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname_idna) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                
                chain = []
                current_cert = x509_cert
                
                while True:
                    cert_dict = process_certificate(current_cert)
                    
                    # Add verification status
                    try:
                        verify_context = ssl.create_default_context()
                        with socket.create_connection((hostname_idna, 443)) as verify_sock:
                            with verify_context.wrap_socket(verify_sock, server_hostname=hostname_idna):
                                cert_dict['verified'] = True
                    except ssl.SSLError as e:
                        cert_dict['verified'] = False
                        cert_dict['verification_error'] = str(e)
                    
                    chain.append(cert_dict)
                    
                    # Check if this is a self-signed certificate
                    if current_cert.issuer == current_cert.subject:
                        break
                        
                    # Try to get the next certificate in the chain
                    try:
                        # Get the AIA extension for the next certificate
                        for extension in current_cert.extensions:
                            if extension.oid == x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                                for access_description in extension.value:
                                    if access_description.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                                        issuer_url = access_description.access_location.value
                                        response = requests.get(issuer_url)
                                        next_cert = x509.load_der_x509_certificate(response.content, default_backend())
                                        current_cert = next_cert
                                        break
                                break
                        else:
                            break
                    except:
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

def main():
    # Get domain from command line argument or prompt
    if len(sys.argv) > 1:
        domain = sys.argv[1].strip()
    else:
        domain = input("Enter domain name (e.g., example.com): ").strip()
    
    print("\n=== 🔒 SSL Certificate Information ===")
    cert_info = get_certificate_info(domain)
    if 'error' not in cert_info:
        print(f"🏢 Issuer: {cert_info['issuer'].get('commonName', 'N/A')}")
        print(f"📅 Valid From: {cert_info['not_before']}")
        print(f"📅 Valid Until: {cert_info['not_after']}")
        
        # Check if certificate is currently valid
        try:
            valid_until = datetime.datetime.strptime(
                cert_info['not_after'].replace(' UTC', ''), 
                '%Y-%m-%d %H:%M:%S'
            ).replace(tzinfo=datetime.UTC)
            
            is_expired = valid_until <= datetime.datetime.now(datetime.UTC)
            if is_expired:
                print("📛 Certificate Status: Expired")
            else:
                print("✅ Certificate Status: Valid")
                
                # Add trust status information
                trust_status = cert_info.get('trust_status', 'unknown')
                if trust_status == 'untrusted_root':
                    print("⚠️  Trust Status: Certificate chain contains untrusted root")
                elif trust_status == 'trusted':
                    print("✅ Trust Status: Certificate chain is trusted")
                elif trust_status == 'expired':
                    print("📛 Trust Status: Certificate has expired")
                else:
                    print("❌ Trust Status: Certificate is invalid")
                    
        except Exception as e:
            print(f"⚠️  Certificate Status: Error parsing date - {str(e)}")
            is_expired = True
        
        if not cert_info.get('verified', True):
            print(f"\n⚠️  Warning: Certificate verification failed")
            print(f"❌ Reason: {cert_info.get('verification_error', 'Unknown')}")
        
        # Only show chain information if certificate is valid
        if not is_expired:
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
        else:
            print("\n⏩ Skipping certificate chain verification for expired certificate")
    else:
        print(f"❌ Error getting certificate: {cert_info['error']}")
    
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

if __name__ == "__main__":
    main()