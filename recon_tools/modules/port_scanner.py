"""
port_scanner.py - Port Scanner & Banner Grabber Module
Scans TCP ports and attempts to grab service banners.
"""

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

# Well-known port to service mapping
SERVICE_MAP = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 69: 'TFTP', 80: 'HTTP',
    110: 'POP3', 111: 'RPC', 119: 'NNTP', 123: 'NTP',
    135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP',
    194: 'IRC', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
    465: 'SMTPS', 514: 'Syslog', 587: 'SMTP-TLS',
    631: 'IPP', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle',
    2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel-SSL',
    2222: 'SSH-alt', 3000: 'Dev-HTTP', 3306: 'MySQL',
    3389: 'RDP', 4444: 'Metasploit', 5432: 'PostgreSQL',
    5900: 'VNC', 5985: 'WinRM', 6379: 'Redis',
    6443: 'K8s-API', 7070: 'RealMedia', 8080: 'HTTP-alt',
    8443: 'HTTPS-alt', 8888: 'HTTP-alt2', 9000: 'PHP-FPM',
    9200: 'Elasticsearch', 9300: 'Elasticsearch-cluster',
    27017: 'MongoDB', 27018: 'MongoDB-shard',
}

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 465, 587, 631, 993, 995, 1080,
    1433, 1521, 2049, 2082, 2083, 2222, 3000, 3306,
    3389, 5432, 5900, 5985, 6379, 8080, 8443, 8888,
    9000, 9200, 27017
]


def grab_banner(sock, port, timeout=2):
    """Attempt to grab a banner from an open socket."""
    banner = ""
    try:
        sock.settimeout(timeout)
        # Send a generic probe for some services
        if port in (80, 8080, 8888):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        elif port == 21:
            pass  # FTP sends banner automatically
        elif port == 22:
            pass  # SSH sends banner automatically
        else:
            sock.send(b"\r\n")

        data = sock.recv(1024)
        banner = data.decode('utf-8', errors='replace').strip()
        # Limit banner length
        banner = banner[:200].replace('\n', ' ').replace('\r', '')
    except Exception:
        pass
    return banner


def scan_port(host, port, timeout=1.5, grab_banners=True):
    """
    Scan a single TCP port.
    Returns: (port, is_open, service, banner)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))

        if result == 0:
            service = SERVICE_MAP.get(port, 'Unknown')
            banner = ""
            if grab_banners:
                banner = grab_banner(sock, port)
            sock.close()
            return port, True, service, banner
        else:
            sock.close()
            return port, False, None, None
    except Exception:
        return port, False, None, None


def scan_ports(host, ports=None, port_range=None, max_workers=150, grab_banners=True, callback=None):
    """
    Scan multiple ports concurrently.

    Args:
        host: Target hostname or IP
        ports: List of specific ports to scan (overrides port_range)
        port_range: Tuple (start, end) for range scan
        max_workers: Thread pool size
        grab_banners: Whether to attempt banner grabbing
        callback: Optional function called with each result (port, is_open, service, banner)

    Returns:
        List of (port, service, banner) for open ports
    """
    open_ports = []

    if ports:
        target_ports = ports
    elif port_range:
        target_ports = range(port_range[0], port_range[1] + 1)
    else:
        target_ports = COMMON_PORTS

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, p, 1.5, grab_banners): p
            for p in target_ports
        }
        for future in as_completed(futures):
            port, is_open, service, banner = future.result()
            if callback:
                callback(port, is_open, service, banner)
            if is_open:
                open_ports.append((port, service, banner))

    return sorted(open_ports, key=lambda x: x[0])


def detect_web_services(open_ports):
    """
    From a list of open ports, identify likely web services.
    Returns list of (port, scheme) tuples.
    """
    web_services = []
    ssl_ports = {443, 8443, 2083, 993, 995, 465, 636}
    http_ports = {80, 8080, 8888, 3000, 9000}

    for port, service, banner in open_ports:
        if port in ssl_ports or 'HTTPS' in (service or ''):
            web_services.append((port, 'https'))
        elif port in http_ports or 'HTTP' in (service or ''):
            web_services.append((port, 'http'))

    return web_services