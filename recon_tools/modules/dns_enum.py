"""
dns_enum.py - DNS Enumeration Module
Performs DNS record lookups and subdomain enumeration.
"""

import socket
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
sys.path.append('/path/to/dnspython')

try:
    import dns.resolver
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def resolve_host(target):
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        return None


def get_dns_records(target):
    """Fetch common DNS record types for a target domain."""
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    if not HAS_DNSPYTHON:
        # Fallback using socket
        try:
            ip = socket.gethostbyname(target)
            results['A'] = [ip]
        except:
            results['A'] = []
        return results, ["dnspython not installed - limited DNS info available"]

    warnings = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            results[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            results[rtype] = []
        except dns.resolver.NXDOMAIN:
            warnings.append(f"Domain {target} does not exist (NXDOMAIN)")
            break
        except dns.resolver.Timeout:
            warnings.append(f"Timeout resolving {rtype} record")
        except Exception as e:
            results[rtype] = []

    return results, warnings


def get_reverse_dns(ip):
    """Perform reverse DNS lookup on an IP address."""
    try:
        if HAS_DNSPYTHON:
            rev = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            answer = resolver.resolve(rev, 'PTR')
            return [str(r) for r in answer]
        else:
            hostname = socket.gethostbyaddr(ip)
            return [hostname[0]]
    except Exception:
        return []


def check_subdomain(subdomain, target, timeout=2):
    """Check if a subdomain exists by resolving it."""
    full = f"{subdomain}.{target}"
    try:
        ip = socket.gethostbyname(full)
        return full, ip
    except socket.gaierror:
        return None, None


def enumerate_subdomains(target, wordlist_path=None, max_workers=50):
    """Brute-force subdomain enumeration using a wordlist."""
    found = []

    if wordlist_path is None:
        # Default wordlist relative to this file
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        wordlist_path = os.path.join(base, 'wordlists', 'subdomains.txt')

    if not os.path.exists(wordlist_path):
        return found, "Wordlist not found"

    with open(wordlist_path, 'r') as f:
        words = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_subdomain, w, target): w for w in words}
        for future in as_completed(futures):
            full, ip = future.result()
            if full and ip:
                found.append((full, ip))

    return sorted(found, key=lambda x: x[0]), None


def get_zone_transfer(target):
    """Attempt DNS zone transfer (AXFR) - usually fails on secure servers."""
    results = []
    if not HAS_DNSPYTHON:
        return results, "dnspython required for zone transfer"

    try:
        resolver = dns.resolver.Resolver()
        ns_records = resolver.resolve(target, 'NS')
        nameservers = [str(ns) for ns in ns_records]

        for ns in nameservers:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, target, timeout=5))
                for name, node in zone.nodes.items():
                    results.append(str(name))
            except Exception:
                pass
    except Exception:
        pass

    return results, None