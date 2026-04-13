"""Web crawler and vulnerability detection service.

Crawls a target website to discover pages, forms, and
potential injection points. Checks for common vulnerabilities
like exposed sensitive files and insecure forms.
"""
import re
import logging
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Sensitive files and directories to check
SENSITIVE_PATHS = [
    '/robots.txt', '/.env', '/.git/config', '/wp-config.php',
    '/admin', '/login', '/phpinfo.php', '/.htaccess',
    '/backup', '/db', '/config', '/api/docs',
    '/sitemap.xml', '/.well-known/security.txt',
    '/wp-admin', '/administrator', '/phpmyadmin',
]

# Patterns that indicate potential vulnerabilities in HTML
VULN_PATTERNS = {
    'inline_script': {
        'pattern': re.compile(r'<script[^>]*>[^<]+</script>', re.IGNORECASE),
        'name': 'Inline JavaScript Found',
        'severity': 'info',
        'description': 'Inline scripts increase XSS attack surface.',
        'recommendation': 'Move JavaScript to external files and use CSP.'
    },
    'password_autocomplete': {
        'pattern': re.compile(r'<input[^>]*type=["\']password["\'][^>]*(?!autocomplete=["\']off["\'])', re.IGNORECASE),
        'name': 'Password Field Without Autocomplete Off',
        'severity': 'low',
        'description': 'Password fields may be cached by the browser.',
        'recommendation': 'Add autocomplete="off" to password input fields.'
    },
    'form_action_http': {
        'pattern': re.compile(r'<form[^>]*action=["\']http://[^"\']+["\']', re.IGNORECASE),
        'name': 'Form Submits Over HTTP',
        'severity': 'high',
        'description': 'Form data sent over unencrypted HTTP can be intercepted.',
        'recommendation': 'Use HTTPS for all form submissions.'
    },
    'email_exposure': {
        'pattern': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        'name': 'Email Address Exposed',
        'severity': 'info',
        'description': 'Email addresses on the page may be harvested by bots.',
        'recommendation': 'Use contact forms instead of displaying email addresses.'
    }
}


class WebCrawler:
    """Crawls websites and identifies potential vulnerabilities."""

    def crawl(self, url, max_pages=50, timeout=10):
        """Crawl a website and analyse pages for vulnerabilities.

        Args:
            url: Starting URL to crawl.
            max_pages: Maximum number of pages to visit.
            timeout: Request timeout per page.

        Returns:
            Dict with discovered pages, forms, links, and vulnerabilities.
        """
        parsed_base = urlparse(url)
        base_domain = parsed_base.netloc

        results = {
            'base_url': url,
            'pages_crawled': [],
            'forms_found': [],
            'external_links': [],
            'sensitive_files': [],
            'vulnerabilities': [],
            'total_pages': 0
        }

        visited = set()
        to_visit = [url]

        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue

            visited.add(current_url)

            try:
                response = requests.get(current_url, timeout=timeout, verify=False,
                                         headers={'User-Agent': 'VulnScanner/1.0'})

                page_info = {
                    'url': current_url,
                    'status': response.status_code,
                    'content_length': len(response.text)
                }
                results['pages_crawled'].append(page_info)

                if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Extract links
                    for link in soup.find_all('a', href=True):
                        href = urljoin(current_url, link['href'])
                        parsed_href = urlparse(href)

                        if parsed_href.netloc == base_domain:
                            if href not in visited and href not in to_visit:
                                to_visit.append(href)
                        else:
                            if href not in [e['url'] for e in results['external_links']]:
                                results['external_links'].append({
                                    'url': href,
                                    'found_on': current_url
                                })

                    # Extract forms
                    for form in soup.find_all('form'):
                        action = form.get('action', '')
                        method = form.get('method', 'GET').upper()
                        inputs = []
                        for inp in form.find_all(['input', 'textarea', 'select']):
                            inputs.append({
                                'name': inp.get('name', ''),
                                'type': inp.get('type', 'text'),
                                'id': inp.get('id', '')
                            })

                        form_info = {
                            'action': urljoin(current_url, action) if action else current_url,
                            'method': method,
                            'inputs': inputs,
                            'found_on': current_url
                        }
                        results['forms_found'].append(form_info)

                        # Check for forms without CSRF tokens
                        has_csrf = any(
                            inp.get('name', '').lower() in ('csrf_token', '_token', 'csrfmiddlewaretoken', '_csrf')
                            for inp in inputs
                        )
                        if method == 'POST' and not has_csrf:
                            results['vulnerabilities'].append({
                                'category': 'xss',
                                'name': 'Form Missing CSRF Token',
                                'severity': 'medium',
                                'description': f'POST form on {current_url} has no CSRF protection.',
                                'recommendation': 'Add CSRF token to all POST forms.',
                                'evidence': f'Form action: {form_info["action"]}'
                            })

                    # Check HTML for vulnerability patterns
                    html = response.text
                    for key, vuln in VULN_PATTERNS.items():
                        matches = vuln['pattern'].findall(html)
                        if matches:
                            results['vulnerabilities'].append({
                                'category': 'xss' if 'script' in key else 'info',
                                'name': vuln['name'],
                                'severity': vuln['severity'],
                                'description': vuln['description'],
                                'recommendation': vuln['recommendation'],
                                'evidence': f'Found on {current_url} ({len(matches)} occurrence(s))'
                            })

            except requests.exceptions.RequestException as e:
                logger.warning("Failed to crawl %s: %s", current_url, e)
            except Exception as e:
                logger.error("Crawl error on %s: %s", current_url, e)

        # Check for sensitive files
        results['sensitive_files'] = self._check_sensitive_files(url, timeout)

        results['total_pages'] = len(results['pages_crawled'])
        return results

    def _check_sensitive_files(self, base_url, timeout):
        """Check for exposed sensitive files and directories.

        Args:
            base_url: Base URL of the target.
            timeout: Request timeout in seconds.

        Returns:
            List of accessible sensitive file dicts.
        """
        found = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in SENSITIVE_PATHS:
            try:
                check_url = base + path
                response = requests.get(check_url, timeout=timeout, verify=False,
                                         headers={'User-Agent': 'VulnScanner/1.0'},
                                         allow_redirects=False)

                if response.status_code == 200:
                    found.append({
                        'path': path,
                        'status': response.status_code,
                        'size': len(response.text)
                    })
            except requests.exceptions.RequestException:
                pass

        return found
