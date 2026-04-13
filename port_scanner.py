"""Port scanning service.

Scans common TCP ports on a target host to identify
open services and potential attack surface.
"""
import socket
import logging
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Common ports with service names and risk info
COMMON_PORTS = {
    21: ('FTP', 'high', 'File transfer - often has weak authentication'),
    22: ('SSH', 'info', 'Secure shell - check for outdated versions'),
    23: ('Telnet', 'critical', 'Unencrypted remote access - should be disabled'),
    25: ('SMTP', 'medium', 'Mail server - may allow open relay'),
    53: ('DNS', 'info', 'Domain name service'),
    80: ('HTTP', 'info', 'Web server - unencrypted'),
    110: ('POP3', 'medium', 'Email retrieval - unencrypted'),
    143: ('IMAP', 'medium', 'Email access - unencrypted'),
    443: ('HTTPS', 'info', 'Web server - encrypted'),
    445: ('SMB', 'high', 'File sharing - common ransomware target'),
    993: ('IMAPS', 'info', 'Secure email access'),
    995: ('POP3S', 'info', 'Secure email retrieval'),
    1433: ('MSSQL', 'high', 'Microsoft SQL Server - should not be public'),
    1521: ('Oracle', 'high', 'Oracle database - should not be public'),
    3306: ('MySQL', 'high', 'MySQL database - should not be public'),
    3389: ('RDP', 'critical', 'Remote desktop - major attack target'),
    5432: ('PostgreSQL', 'high', 'PostgreSQL database - should not be public'),
    5900: ('VNC', 'critical', 'Remote desktop - often poorly secured'),
    6379: ('Redis', 'critical', 'In-memory database - often no authentication'),
    8080: ('HTTP-Alt', 'medium', 'Alternative web server / proxy'),
    8443: ('HTTPS-Alt', 'info', 'Alternative HTTPS'),
    27017: ('MongoDB', 'critical', 'MongoDB - often exposed without auth'),
}


class PortScanner:
    """Scans TCP ports on a target host using socket connections."""

    def scan(self, url, timeout=2):
        """Scan common ports on the target host.

        Args:
            url: Target URL to extract hostname from.
            timeout: Socket connection timeout per port.

        Returns:
            Dict with open/closed ports and vulnerabilities.
        """
        hostname = urlparse(url).netloc.split(':')[0]

        results = {
            'hostname': hostname,
            'open_ports': [],
            'closed_ports': 0,
            'vulnerabilities': [],
            'total_scanned': len(COMMON_PORTS)
        }

        try:
            ip_address = socket.gethostbyname(hostname)
            results['ip_address'] = ip_address
        except socket.gaierror:
            results['error'] = f'Could not resolve hostname: {hostname}'
            return results

        # Scan ports using thread pool for speed
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._check_port, ip_address, port, timeout): port
                for port in COMMON_PORTS
            }

            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                    if is_open:
                        service, severity, desc = COMMON_PORTS[port]
                        port_info = {
                            'port': port,
                            'service': service,
                            'state': 'open',
                            'severity': severity,
                            'description': desc
                        }
                        results['open_ports'].append(port_info)

                        # Add vulnerability for risky open ports
                        if severity in ('high', 'critical'):
                            results['vulnerabilities'].append({
                                'category': 'ports',
                                'name': f'Open port {port} ({service})',
                                'severity': severity,
                                'description': f'Port {port} ({service}) is open. {desc}',
                                'recommendation': f'Close port {port} or restrict access via firewall.',
                                'evidence': f'{ip_address}:{port} - OPEN'
                            })
                    else:
                        results['closed_ports'] += 1
                except Exception:
                    results['closed_ports'] += 1

        # Sort open ports by port number
        results['open_ports'].sort(key=lambda x: x['port'])

        return results

    def _check_port(self, ip, port, timeout):
        """Check if a single TCP port is open.

        Args:
            ip: Target IP address.
            port: Port number to check.
            timeout: Connection timeout in seconds.

        Returns:
            True if port is open, False otherwise.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
