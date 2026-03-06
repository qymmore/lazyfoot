"""
whois_lookup.py - WHOIS Information Module
Retrieves domain registration and ownership information.
"""

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

import socket
import subprocess


def get_whois(target):
    """
    Retrieve WHOIS data for a domain or IP.
    Returns a dict of parsed fields.
    """
    result = {
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'updated_date': None,
        'name_servers': [],
        'status': [],
        'emails': [],
        'org': None,
        'country': None,
        'raw': None,
        'error': None
    }

    if HAS_WHOIS:
        try:
            w = whois.whois(target)
            result['registrar'] = str(w.registrar) if w.registrar else None
            result['org'] = str(w.org) if w.org else None
            result['country'] = str(w.country) if w.country else None

            # Handle dates (can be list or single)
            def fmt_date(d):
                if isinstance(d, list):
                    return [str(x) for x in d]
                return str(d) if d else None

            result['creation_date'] = fmt_date(w.creation_date)
            result['expiration_date'] = fmt_date(w.expiration_date)
            result['updated_date'] = fmt_date(w.updated_date)

            if w.name_servers:
                ns = w.name_servers
                result['name_servers'] = list(ns) if isinstance(ns, (list, set)) else [ns]

            if w.status:
                st = w.status
                result['status'] = list(st) if isinstance(st, list) else [st]

            if w.emails:
                em = w.emails
                result['emails'] = list(em) if isinstance(em, list) else [em]

            result['raw'] = str(w.text)[:2000] if w.text else None

        except Exception as e:
            result['error'] = str(e)
            # Fallback to system whois
            result['raw'] = _system_whois(target)
    else:
        result['error'] = "python-whois not installed"
        result['raw'] = _system_whois(target)

    return result


def _system_whois(target):
    """Fallback: use system whois command if available."""
    try:
        out = subprocess.run(
            ['whois', target],
            capture_output=True, text=True, timeout=10
        )
        return out.stdout[:3000] if out.stdout else None
    except Exception:
        return None


def get_ip_geolocation(ip):
    """
    Attempt basic geolocation via whois for an IP.
    Returns organization and country if available.
    """
    result = {'org': None, 'country': None, 'cidr': None}

    raw = _system_whois(ip)
    if not raw:
        return result

    for line in raw.splitlines():
        lower = line.lower()
        if 'orgname:' in lower or 'org-name:' in lower or 'organisation:' in lower:
            result['org'] = line.split(':', 1)[-1].strip()
        elif lower.startswith('country:'):
            result['country'] = line.split(':', 1)[-1].strip()
        elif 'cidr:' in lower or 'inetnum:' in lower:
            result['cidr'] = line.split(':', 1)[-1].strip()

    return result