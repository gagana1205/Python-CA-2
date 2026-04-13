# VulnScan - Web Vulnerability Scanner

A web-based vulnerability scanner for web applications. Scans for security header misconfigurations, open ports, SSL/TLS issues, and web application vulnerabilities.

## Setup

```
pip install -r requirements.txt
```

## Run

```
python run.py
```

Open http://127.0.0.1:5000 in your browser.

## Features

- User authentication (register/login)
- Full vulnerability scan (headers + ports + SSL + crawler)
- Security headers analysis (CSP, HSTS, X-Frame-Options etc.)
- TCP port scanning (25 common ports)
- SSL/TLS certificate and protocol analysis
- Web crawler with form detection and sensitive file checks
- Scan history with filtering
- Export reports in JSON, XML, CSV
- REST API

## Testing

```
python -m pytest tests/ -v
```

## Tech Stack

- Python 3 / Flask
- SQLite / SQLAlchemy
- Bootstrap 5 / Chart.js
- BeautifulSoup4
- pytest

## Project Structure

```
app/
├── routes/       # auth, dashboard, scans, reports, api
├── services/     # vuln_scanner, header_scanner, port_scanner, ssl_scanner, crawler
├── templates/    # HTML templates
├── static/       # CSS, JS
└── utils/        # security helpers
tests/            # unit and integration tests
```
