"""Security headers analysis service.

Checks HTTP response headers against OWASP security
best practices and identifies missing or misconfigured headers.
"""
import logging
import requests

logger = logging.getLogger(__name__)

# Required security headers and their descriptions
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'Enforces HTTPS connections to prevent MITM attacks.',
        'recommendation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
        'severity': 'high'
    },
    'Content-Security-Policy': {
        'description': 'Prevents XSS and data injection attacks by controlling resource loading.',
        'recommendation': "Add header: Content-Security-Policy: default-src 'self'",
        'severity': 'high'
    },
    'X-Content-Type-Options': {
        'description': 'Prevents MIME-type sniffing attacks.',
        'recommendation': 'Add header: X-Content-Type-Options: nosniff',
        'severity': 'medium'
    },
    'X-Frame-Options': {
        'description': 'Prevents clickjacking attacks by controlling iframe embedding.',
        'recommendation': 'Add header: X-Frame-Options: DENY or SAMEORIGIN',
        'severity': 'medium'
    },
    'X-XSS-Protection': {
        'description': 'Enables browser built-in XSS filtering.',
        'recommendation': 'Add header: X-XSS-Protection: 1; mode=block',
        'severity': 'low'
    },
    'Referrer-Policy': {
        'description': 'Controls how much referrer information is sent with requests.',
        'recommendation': 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
        'severity': 'low'
    },
    'Permissions-Policy': {
        'description': 'Controls which browser features the site can use.',
        'recommendation': 'Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
        'severity': 'low'
    },
    'X-Permitted-Cross-Domain-Policies': {
        'description': 'Controls cross-domain data handling for Flash and PDF.',
        'recommendation': 'Add header: X-Permitted-Cross-Domain-Policies: none',
        'severity': 'info'
    }
}

# Headers that reveal server information (should be removed)
INFO_DISCLOSURE_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']


class HeaderScanner:
    """Analyses HTTP security headers of a target URL."""

    def scan(self, url, timeout=10):
        """Perform security header analysis on a target URL.

        Args:
            url: Target URL to scan.
            timeout: Request timeout in seconds.

        Returns:
            Dict with scan results including present/missing headers and vulnerabilities.
        """
        results = {
            'url': url,
            'status_code': None,
            'headers_present': [],
            'headers_missing': [],
            'info_disclosure': [],
            'vulnerabilities': [],
            'score': 0
        }

        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True,
                                     verify=False, headers={'User-Agent': 'VulnScanner/1.0'})
            results['status_code'] = response.status_code
            response_headers = {k.lower(): v for k, v in response.headers.items()}

            # Check security headers
            present_count = 0
            for header, info in SECURITY_HEADERS.items():
                if header.lower() in response_headers:
                    present_count += 1
                    results['headers_present'].append({
                        'name': header,
                        'value': response_headers[header.lower()],
                        'status': 'present'
                    })
                else:
                    results['headers_missing'].append({
                        'name': header,
                        'severity': info['severity'],
                        'description': info['description'],
                        'recommendation': info['recommendation']
                    })
                    results['vulnerabilities'].append({
                        'category': 'headers',
                        'name': f'Missing {header}',
                        'severity': info['severity'],
                        'description': info['description'],
                        'recommendation': info['recommendation'],
                        'evidence': f'Header {header} not found in response'
                    })

            # Check information disclosure headers
            for header in INFO_DISCLOSURE_HEADERS:
                if header.lower() in response_headers:
                    value = response_headers[header.lower()]
                    results['info_disclosure'].append({
                        'name': header,
                        'value': value
                    })
                    results['vulnerabilities'].append({
                        'category': 'headers',
                        'name': f'Information Disclosure: {header}',
                        'severity': 'info',
                        'description': f'Server exposes {header} header revealing: {value}',
                        'recommendation': f'Remove or suppress the {header} header.',
                        'evidence': f'{header}: {value}'
                    })

            # Check for insecure cookies
            cookies = response.headers.get('Set-Cookie', '')
            if cookies:
                if 'Secure' not in cookies:
                    results['vulnerabilities'].append({
                        'category': 'headers',
                        'name': 'Cookie missing Secure flag',
                        'severity': 'medium',
                        'description': 'Cookies sent without Secure flag can be intercepted over HTTP.',
                        'recommendation': 'Set the Secure flag on all cookies.',
                        'evidence': f'Set-Cookie: {cookies[:100]}'
                    })
                if 'HttpOnly' not in cookies:
                    results['vulnerabilities'].append({
                        'category': 'headers',
                        'name': 'Cookie missing HttpOnly flag',
                        'severity': 'medium',
                        'description': 'Cookies without HttpOnly can be accessed via JavaScript (XSS risk).',
                        'recommendation': 'Set the HttpOnly flag on all cookies.',
                        'evidence': f'Set-Cookie: {cookies[:100]}'
                    })

            # Calculate score (0-100)
            total_headers = len(SECURITY_HEADERS)
            results['score'] = int((present_count / total_headers) * 100)

        except requests.exceptions.SSLError as e:
            results['vulnerabilities'].append({
                'category': 'ssl',
                'name': 'SSL Certificate Error',
                'severity': 'critical',
                'description': f'SSL certificate validation failed: {str(e)[:200]}',
                'recommendation': 'Install a valid SSL certificate from a trusted CA.',
                'evidence': str(e)[:300]
            })
        except requests.exceptions.ConnectionError:
            results['error'] = 'Connection failed. Target may be unreachable.'
        except requests.exceptions.Timeout:
            results['error'] = 'Connection timed out.'
        except Exception as e:
            results['error'] = f'Scan error: {str(e)[:200]}'

        return results
