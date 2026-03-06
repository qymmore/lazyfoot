"""
web_recon.py - Web Reconnaissance Module
Analyzes HTTP/HTTPS services for information and misconfigurations.
"""

import ssl
import socket
import datetime
import urllib.parse
import re

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS - Forces HTTPS connections',
    'Content-Security-Policy': 'CSP - Prevents XSS and injection attacks',
    'X-Frame-Options': 'Prevents clickjacking attacks',
    'X-Content-Type-Options': 'Prevents MIME type sniffing',
    'Referrer-Policy': 'Controls referrer information',
    'Permissions-Policy': 'Controls browser features/APIs',
    'X-XSS-Protection': 'Legacy XSS filter (deprecated but still checked)',
    'Cross-Origin-Opener-Policy': 'Isolates browsing context',
    'Cross-Origin-Resource-Policy': 'Controls resource sharing',
}

DANGEROUS_HEADERS = {
    'Server': 'Reveals server software and version',
    'X-Powered-By': 'Reveals backend technology',
    'X-AspNet-Version': 'Reveals ASP.NET version',
    'X-Generator': 'Reveals CMS or framework',
}

COMMON_PATHS = [
    '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
    '/admin', '/admin/', '/administrator', '/login', '/wp-login.php',
    '/wp-admin', '/wp-content', '/phpmyadmin', '/pma',
    '/backup', '/backup.zip', '/backup.tar.gz',
    '/.env', '/.git/config', '/.htaccess',
    '/config.php', '/configuration.php', '/settings.php',
    '/server-status', '/server-info', '/info.php', '/phpinfo.php',
    '/readme.html', '/readme.txt', '/CHANGELOG.txt', '/VERSION',
    '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/api', '/api/v1', '/api/swagger', '/swagger.json',
    '/actuator', '/actuator/env', '/actuator/health',
    '/_cpanel', '/webmail', '/mail',
]

CMS_FINGERPRINTS = {
    'WordPress': ['/wp-login.php', '/wp-content/', '/wp-includes/'],
    'Drupal': ['/sites/default/', '/modules/', '/misc/drupal.js'],
    'Joomla': ['/components/', '/modules/mod_', '/administrator/'],
    'Magento': ['/skin/frontend/', '/js/mage/', '/downloader/'],
    'Laravel': ['/storage/logs/', '/public/index.php'],
    'Django': ['csrfmiddlewaretoken', 'django'],
    'Shopify': ['cdn.shopify.com', 'myshopify.com'],
}


def make_request(url, method='GET', timeout=8, allow_redirects=True, verify=False):
    """Perform an HTTP request and return response or None."""
    if not HAS_REQUESTS:
        return None, "requests library not installed"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0; +https://github.com/recon)',
            'Accept': 'text/html,application/xhtml+xml,*/*',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        resp = requests.request(
            method, url,
            headers=headers,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify
        )
        return resp, None
    except requests.exceptions.ConnectionError:
        return None, "Connection refused"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except Exception as e:
        return None, str(e)


def analyze_headers(response):
    """Analyze HTTP response headers for security issues."""
    headers = dict(response.headers)
    result = {
        'missing_security': [],
        'info_disclosure': [],
        'present_security': [],
        'all_headers': headers,
        'status_code': response.status_code,
        'server': headers.get('Server', 'Not disclosed'),
        'content_type': headers.get('Content-Type', 'Unknown'),
    }

    for h, desc in SECURITY_HEADERS.items():
        if h in headers:
            result['present_security'].append((h, headers[h], desc))
        else:
            result['missing_security'].append((h, desc))

    for h, desc in DANGEROUS_HEADERS.items():
        if h in headers:
            result['info_disclosure'].append((h, headers[h], desc))

    # Check cookie flags
    set_cookie = headers.get('Set-Cookie', '')
    if set_cookie:
        cookie_issues = []
        if 'HttpOnly' not in set_cookie:
            cookie_issues.append('Missing HttpOnly flag')
        if 'Secure' not in set_cookie:
            cookie_issues.append('Missing Secure flag')
        if 'SameSite' not in set_cookie:
            cookie_issues.append('Missing SameSite attribute')
        result['cookie_issues'] = cookie_issues
    else:
        result['cookie_issues'] = []

    return result


def get_ssl_info(host, port=443):
    """Retrieve SSL/TLS certificate information."""
    result = {
        'subject': {},
        'issuer': {},
        'version': None,
        'not_before': None,
        'not_after': None,
        'expired': False,
        'days_until_expiry': None,
        'san': [],
        'error': None
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result['version'] = ssock.version()

                if cert:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    result['subject'] = subject
                    result['issuer'] = issuer

                    not_after_str = cert.get('notAfter', '')
                    not_before_str = cert.get('notBefore', '')
                    result['not_before'] = not_before_str
                    result['not_after'] = not_after_str

                    if not_after_str:
                        try:
                            exp = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                            now = datetime.datetime.utcnow()
                            delta = exp - now
                            result['days_until_expiry'] = delta.days
                            result['expired'] = delta.days < 0
                        except Exception:
                            pass

                    # Subject Alternative Names
                    san_list = cert.get('subjectAltName', [])
                    result['san'] = [v for t, v in san_list if t == 'DNS']

    except ssl.SSLError as e:
        result['error'] = f"SSL Error: {e}"
    except ConnectionRefusedError:
        result['error'] = "Port 443 not open"
    except Exception as e:
        result['error'] = str(e)

    return result


def check_paths(base_url, paths=None, timeout=5):
    """Check for existence of common/sensitive paths."""
    if not HAS_REQUESTS:
        return []

    if paths is None:
        paths = COMMON_PATHS

    found = []
    for path in paths:
        url = base_url.rstrip('/') + path
        try:
            resp, err = make_request(url, timeout=timeout, allow_redirects=False)
            if resp is not None and resp.status_code not in (404, 403, 410):
                found.append({
                    'path': path,
                    'url': url,
                    'status': resp.status_code,
                    'size': len(resp.content),
                    'redirect': resp.headers.get('Location', '')
                })
        except Exception:
            pass
    return found


def detect_cms(base_url, response_body=""):
    """Detect CMS/framework from response content and known paths."""
    detected = []
    body_lower = response_body.lower() if response_body else ""

    for cms, indicators in CMS_FINGERPRINTS.items():
        for indicator in indicators:
            if indicator.startswith('/'):
                url = base_url.rstrip('/') + indicator
                resp, _ = make_request(url, timeout=5, allow_redirects=False)
                if resp and resp.status_code in (200, 301, 302, 403):
                    detected.append(cms)
                    break
            elif indicator.lower() in body_lower:
                detected.append(cms)
                break

    return list(set(detected))


def fetch_robots_txt(base_url):
    """Fetch and parse robots.txt for hidden paths."""
    url = base_url.rstrip('/') + '/robots.txt'
    resp, err = make_request(url)
    if err or not resp or resp.status_code != 200:
        return None, []

    disallowed = []
    for line in resp.text.splitlines():
        if line.lower().startswith('disallow:'):
            path = line.split(':', 1)[-1].strip()
            if path and path != '/':
                disallowed.append(path)
    return resp.text, disallowed


def check_clickjacking(response):
    """Check if the page is vulnerable to clickjacking."""
    headers = response.headers
    xfo = headers.get('X-Frame-Options', '')
    csp = headers.get('Content-Security-Policy', '')

    if xfo.upper() in ('DENY', 'SAMEORIGIN'):
        return False, f"Protected via X-Frame-Options: {xfo}"
    if 'frame-ancestors' in csp.lower():
        return False, f"Protected via CSP frame-ancestors"
    return True, "No clickjacking protection found (missing X-Frame-Options / CSP frame-ancestors)"


def detect_technologies(response):
    """Detect technologies from headers and response body."""
    tech = []
    headers = response.headers
    body = response.text[:5000] if response.text else ""

    # From headers
    server = headers.get('Server', '')
    powered = headers.get('X-Powered-By', '')
    if server: tech.append(f"Server: {server}")
    if powered: tech.append(f"Powered by: {powered}")

    # From body
    patterns = {
        'jQuery': r'jquery[.-](\d+\.\d+)',
        'Bootstrap': r'bootstrap[.-](\d+\.\d+)',
        'React': r'react[.-](\d+\.\d+)',
        'Angular': r'angular[.-](\d+\.\d+)',
        'Vue.js': r'vue[.-](\d+\.\d+)',
        'WordPress': r'wp-content|wp-includes',
        'Google Analytics': r'google-analytics\.com|gtag\(',
        'Cloudflare': r'cloudflare',
        'nginx': r'nginx/[\d.]+',
        'Apache': r'Apache/[\d.]+',
    }
    for name, pattern in patterns.items():
        if re.search(pattern, body + server, re.IGNORECASE):
            match = re.search(pattern, body + server, re.IGNORECASE)
            if match and match.group(0) != match.string:
                tech.append(f"{name}: {match.group(0)}")
            else:
                tech.append(name)

    return list(set(tech))