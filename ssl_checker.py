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
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich import print as rprint

warnings.filterwarnings('ignore', category=DeprecationWarning)

console = Console()

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
        input_domain = console.input("[bold blue]Enter domain name[/] (e.g., example.com): ").strip()
    
    try:
        domain = clean_domain(input_domain)
    except ValueError as e:
        console.print(f"[red]❌ Error:[/] {str(e)}")
        console.print("[yellow]Please enter a valid domain name (e.g., example.com)[/]")
        return
    
    console.print(f"\n[bold]Checking domain:[/] {domain}")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task1 = progress.add_task("⏳ Checking SSL certificate...", total=None)
        cert_info = get_certificate_info(domain)
        progress.update(task1, description="✓ SSL certificate checked")
        
        if 'error' not in cert_info:
            # SSL Certificate Information Panel
            console.print(Panel.fit(
                "\n".join([
                    f"[bold]🏢 Issuer:[/] {cert_info['issuer'].get('commonName', 'N/A')}",
                    f"[bold]📅 Valid From:[/] {cert_info['not_before']}",
                    f"[bold]📅 Valid Until:[/] {cert_info['not_after']}"
                ]),
                title="🔒 SSL Certificate Information",
                border_style="blue"
            ))
            
            # HPKP Check
            task2 = progress.add_task("⏳ Checking HPKP configuration...", total=None)
            hpkp_info = check_hpkp(domain)
            progress.update(task2, description="✓ HPKP configuration checked")
            
            # HPKP Information Panel
            if 'error' not in hpkp_info:
                status = "[green]✅ HPKP is enabled[/]" if hpkp_info['has_hpkp'] else "[yellow]❌ HPKP is not enabled[/]"
                console.print(Panel.fit(
                    f"[bold]Status:[/] {status}",
                    title="📌 HPKP Information",
                    border_style="blue"
                ))
            
            # Certificate Validation
            task3 = progress.add_task("⏳ Checking certificate validation...", total=None)
            try:
                valid_until = datetime.datetime.strptime(
                    cert_info['not_after'].replace(' UTC', ''), 
                    '%Y-%m-%d %H:%M:%S'
                ).replace(tzinfo=datetime.UTC)
                
                is_expired = valid_until <= datetime.datetime.now(datetime.UTC)
                trust_status = cert_info.get('trust_status', 'unknown')
                
                # First check expiration
                if is_expired:
                    console.print("[red]📛 Certificate Status: Expired[/]")
                else:
                    # Then check trust status
                    if trust_status == 'trusted':
                        console.print("[green]✅ Certificate Status: Valid and Trusted[/]")
                    else:
                        console.print("[red]❌ Certificate Status: Invalid[/]")
                    
                    # Show detailed trust status
                    if trust_status == 'revoked':
                        console.print("[red]🚫 Trust Status: Certificate has been revoked[/]")
                    elif trust_status == 'untrusted_root':
                        console.print("[yellow]⚠️  Trust Status: Certificate chain contains untrusted root[/]")
                    elif trust_status == 'expired':
                        console.print("[red]📛 Trust Status: Certificate has expired[/]")
                    elif trust_status == 'trusted':
                        console.print("[green]✅ Trust Status: Certificate chain is trusted[/]")
                        if 'crl_checked' in cert_info and not cert_info['crl_checked']:
                            console.print("[yellow]⚠️  Note: CRL verification unavailable[/]")
                    else:
                        console.print("[red]❌ Trust Status: Certificate validation failed[/]")
                    
                    if not cert_info.get('verified', True):
                        console.print("[yellow]⚠️  Warning: Certificate verification failed[/]")
                        console.print(f"[red]❌ Reason: {cert_info.get('verification_error', 'Unknown')}[/]")
                    
                    # Exit early only if there are serious issues
                    if is_expired or trust_status in ['revoked', 'untrusted_root', 'invalid']:
                        console.print("[red]❌ Certificate validation failed. Skipping additional checks.[/]")
                        return
                    
                    # Only continue with chain and DNS if certificate is valid
                    progress.add_task(description="Getting certificate chain...", total=None)
                    console.print("[bold]=== 🔗 Certificate Chain ===[/]")
                    chain = get_certificate_chain(domain)
                    for i, cert in enumerate(chain, 1):
                        if 'error' not in cert:
                            console.print(f"[bold]Certificate {i}:[/]")
                            console.print(f"[bold]📌 Version: {cert['version']}[/]")
                            console.print(f"[bold]🔑 Serial Number: {cert['serial_number']}[/]")
                            
                            console.print("[bold]👤 Subject:[/]")
                            for key, value in cert['subject'].items():
                                console.print(f"  {key}: {value}")
                            
                            console.print("[bold]📝 Issuer:[/]")
                            for key, value in cert['issuer'].items():
                                console.print(f"  {key}: {value}")
                            
                            console.print(f"[bold]⏰ Validity Period:[/]")
                            console.print(f"  Not Before: {cert['not_before']}")
                            console.print(f"  Not After: {cert['not_after']}")
                            console.print(f"[bold]🔏 Signature Algorithm:[/] {cert['signature_algorithm']}")
                            
                            if cert['subject_alt_names']:
                                console.print("[bold]🔄 Subject Alternative Names:[/]")
                                for san in cert['subject_alt_names']:
                                    console.print(f"  {san}")
                        else:
                            console.print(f"[red]❌ Error getting chain: {cert['error']}[/]")
                    
                    # DNS Information
                    progress.add_task(description="Getting DNS information...", total=None)
                    console.print("[bold]=== 🌐 DNS Information ===[/]")
                    dns_info = get_dns_info(domain)
                    if 'error' not in dns_info:
                        console.print("[bold]📍 IPv4 Addresses:[/]")
                        for ip in dns_info['a_records']:
                            console.print(f"  • {ip}")
                        
                        if dns_info['aaaa_records']:
                            console.print("[bold]📍 IPv6 Addresses:[/]")
                            for ip in dns_info['aaaa_records']:
                                console.print(f"  • {ip}")
                        
                        console.print("[bold]🌍 IP Information:[/]")
                        for ip_data in dns_info['ip_info']:
                            if 'error' not in ip_data:
                                console.print(f"[bold]🔍 {ip_data['ip']}:[/]")
                                console.print(f"  🗺️  Country: {ip_data.get('country', 'N/A')}")
                                console.print(f"  🏙️  City: {ip_data.get('city', 'N/A')}")
                                console.print(f"  🏢 Organization: {ip_data.get('org', 'N/A')}")
                            else:
                                console.print(f"[red]❌ {ip_data['ip']}: Error fetching information[/]")
                    else:
                        console.print(f"[red]❌ Error getting DNS information: {dns_info['error']}[/]")
                    
            except Exception as e:
                console.print("[yellow]⚠️  Certificate Status: Error parsing date - {str(e)}[/]")
        else:
            console.print(f"[red]❌ Error getting certificate: {cert_info['error']}[/]")

if __name__ == "__main__":
    main()