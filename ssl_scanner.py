"""SSL/TLS certificate analysis service.

Checks SSL certificate validity, expiry, protocol version,
and cipher strength for a target host.
"""
import ssl
import socket
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class SSLScanner:
    """Analyses SSL/TLS configuration of a target host."""

    def scan(self, url, timeout=10):
        """Perform SSL/TLS analysis on a target URL.

        Args:
            url: Target URL to scan.
            timeout: Connection timeout in seconds.

        Returns:
            Dict with certificate details, protocol info, and vulnerabilities.
        """
        hostname = urlparse(url).netloc.split(':')[0]
        port = 443

        results = {
            'hostname': hostname,
            'certificate': {},
            'protocol': None,
            'cipher': None,
            'vulnerabilities': []
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cert_bin = ssock.getpeercert(binary_form=True)
                    results['protocol'] = ssock.version()
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        results['cipher'] = {
                            'name': cipher_info[0],
                            'protocol': cipher_info[1],
                            'bits': cipher_info[2]
                        }

            # Get certificate with verification to check validity
            try:
                ctx_verify = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=timeout) as sock2:
                    with ctx_verify.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                        cert = ssock2.getpeercert()
                        results['certificate'] = self._parse_cert(cert, hostname)
                        results['cert_valid'] = True
            except ssl.SSLCertVerificationError as e:
                results['cert_valid'] = False
                results['vulnerabilities'].append({
                    'category': 'ssl',
                    'name': 'Invalid SSL Certificate',
                    'severity': 'critical',
                    'description': f'SSL certificate verification failed: {str(e)[:200]}',
                    'recommendation': 'Install a valid SSL certificate from a trusted Certificate Authority.',
                    'evidence': str(e)[:300]
                })
                # Still parse what we can from unverified cert
                ctx_noverify = ssl.create_default_context()
                ctx_noverify.check_hostname = False
                ctx_noverify.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=timeout) as sock3:
                    with ctx_noverify.wrap_socket(sock3, server_hostname=hostname) as ssock3:
                        cert = ssock3.getpeercert()
                        if cert:
                            results['certificate'] = self._parse_cert(cert, hostname)

            # Check protocol version vulnerabilities
            if results['protocol']:
                proto = results['protocol']
                if 'SSLv' in proto or proto == 'TLSv1' or proto == 'TLSv1.1':
                    results['vulnerabilities'].append({
                        'category': 'ssl',
                        'name': f'Outdated Protocol: {proto}',
                        'severity': 'high',
                        'description': f'{proto} is deprecated and has known vulnerabilities.',
                        'recommendation': 'Upgrade to TLS 1.2 or TLS 1.3.',
                        'evidence': f'Negotiated protocol: {proto}'
                    })

            # Check cipher strength
            if results['cipher']:
                bits = results['cipher']['bits']
                cipher_name = results['cipher']['name']
                if bits < 128:
                    results['vulnerabilities'].append({
                        'category': 'ssl',
                        'name': 'Weak Cipher Suite',
                        'severity': 'high',
                        'description': f'Cipher {cipher_name} uses only {bits}-bit encryption.',
                        'recommendation': 'Configure server to use 256-bit ciphers.',
                        'evidence': f'Cipher: {cipher_name} ({bits} bits)'
                    })

            # Check certificate expiry
            cert_info = results.get('certificate', {})
            if cert_info.get('days_until_expiry') is not None:
                days = cert_info['days_until_expiry']
                if days < 0:
                    results['vulnerabilities'].append({
                        'category': 'ssl',
                        'name': 'Expired SSL Certificate',
                        'severity': 'critical',
                        'description': f'Certificate expired {abs(days)} days ago.',
                        'recommendation': 'Renew the SSL certificate immediately.',
                        'evidence': f'Expiry: {cert_info.get("not_after", "N/A")}'
                    })
                elif days < 30:
                    results['vulnerabilities'].append({
                        'category': 'ssl',
                        'name': 'SSL Certificate Expiring Soon',
                        'severity': 'medium',
                        'description': f'Certificate expires in {days} days.',
                        'recommendation': 'Renew the SSL certificate before expiry.',
                        'evidence': f'Expiry: {cert_info.get("not_after", "N/A")}'
                    })

        except socket.gaierror:
            results['error'] = f'Could not resolve hostname: {hostname}'
        except ConnectionRefusedError:
            results['error'] = f'Connection refused on port {port}. SSL may not be enabled.'
        except socket.timeout:
            results['error'] = 'Connection timed out.'
        except Exception as e:
            results['error'] = f'SSL scan error: {str(e)[:200]}'

        return results

    def _parse_cert(self, cert, hostname):
        """Parse SSL certificate details.

        Args:
            cert: Certificate dict from ssl module.
            hostname: Target hostname for CN matching.

        Returns:
            Parsed certificate information dict.
        """
        if not cert:
            return {}

        info = {}

        # Subject
        subject = dict(x[0] for x in cert.get('subject', []))
        info['common_name'] = subject.get('commonName', 'N/A')
        info['organization'] = subject.get('organizationName', 'N/A')

        # Issuer
        issuer = dict(x[0] for x in cert.get('issuer', []))
        info['issuer'] = issuer.get('organizationName', 'N/A')
        info['issuer_cn'] = issuer.get('commonName', 'N/A')

        # Validity dates
        not_before = cert.get('notBefore', '')
        not_after = cert.get('notAfter', '')
        info['not_before'] = not_before
        info['not_after'] = not_after

        # Calculate days until expiry
        try:
            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            info['days_until_expiry'] = (expiry - datetime.utcnow()).days
        except (ValueError, TypeError):
            info['days_until_expiry'] = None

        # SANs
        san_list = cert.get('subjectAltName', [])
        info['san'] = [name for type_, name in san_list if type_ == 'DNS']

        # Serial number
        info['serial_number'] = cert.get('serialNumber', 'N/A')

        return info
