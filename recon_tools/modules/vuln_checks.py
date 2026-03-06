"""
vuln_checks.py - Web Vulnerability Detection Module
Performs passive and light-touch vulnerability checks.
NOTE: For authorized security testing only.
"""

import re
import urllib.parse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# SQL error signatures
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql_",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "ora-01756",
    "postgresql error",
    "pg_query(): query failed",
    "sqlite_exception",
    "syntax error near",
    "division by zero",
    "supplied argument is not a valid mysql",
    "mysql_num_rows() expects parameter",
    "invalid query: ",
    "sql syntax.*mysql",
    "valid mysql result",
    "mysqlclient",
]

# XSS test payloads (passive detection only)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "javascript:alert(1)",
]

# Common injectable parameters
INJECTABLE_PARAMS = ['id', 'page', 'cat', 'search', 'q', 'query', 'item',
                     'view', 'type', 'user', 'name', 'key', 'token', 'file',
                     'path', 'url', 'redirect', 'next', 'return', 'ref']


def _make_request(url, params=None, timeout=8, verify=False):
    if not HAS_REQUESTS:
        return None
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'}
        r = requests.get(url, params=params, headers=headers,
                         timeout=timeout, verify=verify, allow_redirects=True)
        return r
    except Exception:
        return None


def check_sqli_basic(base_url, params=None):
    """
    Basic SQL injection error detection.
    Appends a single quote to parameter values and checks for DB error messages.
    This is detection-only, not exploitation.
    """
    findings = []
    if not HAS_REQUESTS:
        return findings

    # Parse existing URL params
    parsed = urllib.parse.urlparse(base_url)
    existing_params = dict(urllib.parse.parse_qsl(parsed.query))

    # Combine with provided params
    test_params = {**existing_params, **(params or {})}

    # If no params found, try common ones with dummy values
    if not test_params:
        test_params = {p: '1' for p in INJECTABLE_PARAMS[:5]}

    for param_name, param_val in test_params.items():
        # Test with single quote
        test_val = str(param_val) + "'"
        test_p = {**test_params, param_name: test_val}

        resp = _make_request(base_url, params=test_p)
        if resp is None:
            continue

        body_lower = resp.text.lower()
        for error_sig in SQL_ERRORS:
            if re.search(error_sig, body_lower):
                findings.append({
                    'type': 'SQL Injection (Error-Based)',
                    'severity': 'HIGH',
                    'parameter': param_name,
                    'evidence': f"DB error signature found: '{error_sig}'",
                    'url': resp.url,
                })
                break

    return findings


def check_xss_reflection(base_url, params=None):
    """
    Check if user input is reflected in the response without encoding.
    This is a passive reflection check, not a full exploit.
    """
    findings = []
    if not HAS_REQUESTS:
        return findings

    parsed = urllib.parse.urlparse(base_url)
    existing_params = dict(urllib.parse.parse_qsl(parsed.query))
    test_params = {**existing_params, **(params or {})}

    if not test_params:
        test_params = {'q': 'test', 'search': 'test'}

    # Use a unique marker that's obviously a test payload
    marker = "RECONTEST123XSS"
    probe = f"{marker}<b>"

    for param_name in list(test_params.keys())[:5]:
        test_p = {**test_params, param_name: probe}
        resp = _make_request(base_url, params=test_p)
        if resp is None:
            continue

        if marker in resp.text and '<b>' in resp.text:
            findings.append({
                'type': 'Reflected XSS (Potential)',
                'severity': 'HIGH',
                'parameter': param_name,
                'evidence': f"Input reflected unencoded in response",
                'url': resp.url,
            })

    return findings


def check_open_redirect(base_url):
    """
    Check for open redirect vulnerabilities in common redirect parameters.
    """
    findings = []
    if not HAS_REQUESTS:
        return findings

    redirect_params = ['url', 'redirect', 'redirect_url', 'next', 'return',
                       'return_url', 'goto', 'destination', 'link', 'ref']
    test_domain = "https://evil-test-domain-12345.com"

    for param in redirect_params:
        resp = _make_request(base_url, params={param: test_domain}, timeout=5)
        if resp is None:
            continue

        # Check if we ended up at the test domain (shouldn't happen)
        if test_domain in resp.url or test_domain in resp.text[:500]:
            findings.append({
                'type': 'Open Redirect',
                'severity': 'MEDIUM',
                'parameter': param,
                'evidence': f"Parameter '{param}' may allow external redirects",
                'url': f"{base_url}?{param}={test_domain}",
            })

    return findings


def check_directory_listing(base_url):
    """Check if directory listing is enabled on common directories."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    dirs_to_check = ['/images/', '/uploads/', '/files/', '/backup/',
                     '/assets/', '/static/', '/media/', '/css/', '/js/']

    dir_listing_sigs = [
        'index of /', 'directory listing', 'parent directory',
        '[to parent directory]', 'directory of /'
    ]

    for d in dirs_to_check:
        url = base_url.rstrip('/') + d
        resp = _make_request(url)
        if resp is None or resp.status_code not in (200, 301, 302):
            continue

        body_lower = resp.text.lower()
        for sig in dir_listing_sigs:
            if sig in body_lower:
                findings.append({
                    'type': 'Directory Listing Enabled',
                    'severity': 'MEDIUM',
                    'parameter': 'N/A',
                    'evidence': f"Directory listing at {d}",
                    'url': url,
                })
                break

    return findings


def check_sensitive_file_exposure(base_url):
    """Check for exposed sensitive files."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    sensitive_files = {
        '/.env': ['DB_PASSWORD', 'SECRET_KEY', 'API_KEY', 'AWS_'],
        '/.git/config': ['[core]', '[remote', 'url ='],
        '/config.php': ['$db_', 'password', 'mysql'],
        '/wp-config.php': ['DB_PASSWORD', 'table_prefix', 'AUTH_KEY'],
        '/phpinfo.php': ['PHP Version', 'phpinfo()'],
        '/info.php': ['PHP Version', 'phpinfo()'],
        '/.htpasswd': [':$apr1$', ':{SHA}'],
        '/database.yml': ['password:', 'adapter:', 'hostname:'],
        '/settings.py': ['SECRET_KEY', 'DATABASES', 'PASSWORD'],
        '/docker-compose.yml': ['password:', 'MYSQL_ROOT', 'postgres'],
    }

    for path, signatures in sensitive_files.items():
        url = base_url.rstrip('/') + path
        resp = _make_request(url, timeout=5)
        if resp is None or resp.status_code != 200:
            continue

        body_lower = resp.text.lower()
        for sig in signatures:
            if sig.lower() in body_lower:
                findings.append({
                    'type': 'Sensitive File Exposed',
                    'severity': 'CRITICAL',
                    'parameter': 'N/A',
                    'evidence': f"File {path} is accessible and contains sensitive content",
                    'url': url,
                })
                break

    return findings


def check_cors_misconfiguration(base_url):
    """Check for CORS misconfiguration."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    try:
        headers = {
            'Origin': 'https://evil.attacker.com',
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
        }
        resp = requests.get(base_url, headers=headers, timeout=8, verify=False)
        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '')

        if acao == '*':
            findings.append({
                'type': 'CORS Misconfiguration (Wildcard)',
                'severity': 'MEDIUM',
                'parameter': 'Access-Control-Allow-Origin',
                'evidence': 'ACAO header set to wildcard (*)',
                'url': base_url,
            })
        elif 'evil.attacker.com' in acao:
            sev = 'CRITICAL' if acac.lower() == 'true' else 'HIGH'
            findings.append({
                'type': 'CORS Misconfiguration (Origin Reflection)',
                'severity': sev,
                'parameter': 'Access-Control-Allow-Origin',
                'evidence': f"Server reflects arbitrary Origin. Credentials: {acac}",
                'url': base_url,
            })
    except Exception:
        pass

    return findings


def check_http_methods(base_url):
    """Check for dangerous HTTP methods enabled (PUT, DELETE, TRACE)."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
    try:
        resp = requests.options(base_url, timeout=8, verify=False,
                                headers={'User-Agent': 'SecurityScanner/1.0'})
        allow = resp.headers.get('Allow', '') + resp.headers.get('Public', '')
        enabled = [m for m in dangerous if m in allow.upper()]
        if enabled:
            findings.append({
                'type': 'Dangerous HTTP Methods Enabled',
                'severity': 'MEDIUM',
                'parameter': 'Allow header',
                'evidence': f"Enabled methods: {', '.join(enabled)}",
                'url': base_url,
            })
    except Exception:
        pass

    return findings


def run_all_checks(base_url, enable_active=True):
    """
    Run all vulnerability checks against a base URL.
    Returns categorized findings.
    """
    all_findings = []

    checks = [
        ("Sensitive File Exposure", check_sensitive_file_exposure),
        ("Directory Listing", check_directory_listing),
        ("CORS Misconfiguration", check_cors_misconfiguration),
        ("HTTP Methods", check_http_methods),
    ]

    if enable_active:
        checks += [
            ("SQL Injection (basic)", check_sqli_basic),
            ("XSS Reflection", check_xss_reflection),
            ("Open Redirect", check_open_redirect),
        ]

    for check_name, check_func in checks:
        try:
            results = check_func(base_url)
            all_findings.extend(results)
        except Exception:
            pass

    return all_findings