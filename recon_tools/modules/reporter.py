"""
reporter.py - Output and Reporting Module
Handles colored terminal output and report file generation.
"""

import json
import datetime
import sys
import os

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    # Stub colorama classes
    class _Stub:
        def __getattr__(self, name): return ''
    Fore = Back = Style = _Stub()


SEVERITY_COLORS = {
    'CRITICAL': Fore.RED + Style.BRIGHT,
    'HIGH': Fore.RED,
    'MEDIUM': Fore.YELLOW,
    'LOW': Fore.CYAN,
    'INFO': Fore.WHITE,
}


def _c(color_code, text):
    return f"{color_code}{text}{Style.RESET_ALL}" if HAS_COLOR else text


def banner():
    b = f"""
{Fore.CYAN}{Style.BRIGHT}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Style.RESET_ALL}
  {Fore.YELLOW}Enumeration, Footprinting & Web Vulnerability Scanner{Style.RESET_ALL}
  {Fore.RED}For authorized security testing only.{Style.RESET_ALL}
    """
    print(b)


def section(title):
    width = 60
    print(f"\n{Fore.CYAN}{'═' * width}")
    print(f"  {Style.BRIGHT}{title}")
    print(f"{Fore.CYAN}{'═' * width}{Style.RESET_ALL}")


def subsection(title):
    print(f"\n{Fore.BLUE}{Style.BRIGHT}  ▶ {title}{Style.RESET_ALL}")


def item(label, value, color=None):
    if color:
        print(f"    {Fore.WHITE}{label}:{Style.RESET_ALL} {color}{value}{Style.RESET_ALL}")
    else:
        print(f"    {Fore.WHITE}{label}:{Style.RESET_ALL} {value}")


def success(msg):
    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def warning(msg):
    print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def error(msg):
    print(f"  {Fore.RED}[-]{Style.RESET_ALL} {msg}")


def info(msg):
    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} {msg}")


def vuln(finding):
    sev = finding.get('severity', 'INFO')
    color = SEVERITY_COLORS.get(sev, Fore.WHITE)
    print(f"\n    {color}[{sev}] {finding['type']}{Style.RESET_ALL}")
    print(f"      Parameter : {finding.get('parameter', 'N/A')}")
    print(f"      Evidence  : {finding.get('evidence', '')}")
    print(f"      URL       : {finding.get('url', '')}")


def print_open_ports(ports):
    if not ports:
        warning("No open ports found")
        return
    print(f"\n    {'PORT':<8} {'SERVICE':<16} {'BANNER'}")
    print(f"    {'-'*60}")
    for port, service, banner in ports:
        banner_short = (banner[:45] + '...') if banner and len(banner) > 45 else (banner or '')
        print(f"    {Fore.GREEN}{port:<8}{Style.RESET_ALL} {service:<16} {Fore.WHITE}{banner_short}{Style.RESET_ALL}")


def print_dns_records(records):
    for rtype, values in records.items():
        if values:
            print(f"\n    {Fore.YELLOW}{rtype}{Style.RESET_ALL}")
            for v in values:
                print(f"      {v}")


def print_subdomains(subdomains):
    if not subdomains:
        warning("No subdomains found")
        return
    for full, ip in subdomains:
        print(f"    {Fore.GREEN}{full:<40}{Style.RESET_ALL} {ip}")


def print_paths(paths):
    if not paths:
        return
    print(f"\n    {'STATUS':<8} {'SIZE':<10} {'PATH'}")
    print(f"    {'-'*60}")
    for p in paths:
        status = p['status']
        color = Fore.GREEN if status == 200 else Fore.YELLOW
        print(f"    {color}{status:<8}{Style.RESET_ALL} {p['size']:<10} {p['path']}")


def generate_report(data, output_path):
    """Generate a text/JSON report file."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    target = data.get('target', 'unknown')

    lines = []
    lines.append("=" * 70)
    lines.append(f"  RECON SCAN REPORT — {target}")
    lines.append(f"  Generated: {timestamp}")
    lines.append("=" * 70)

    # DNS
    if 'dns' in data:
        lines.append("\n[DNS RECORDS]")
        for rtype, vals in data['dns'].items():
            if vals:
                lines.append(f"  {rtype}: {', '.join(vals)}")

    # IP / WHOIS
    if 'ip' in data:
        lines.append(f"\n[HOST]")
        lines.append(f"  IP: {data['ip']}")
    if 'whois' in data:
        w = data['whois']
        lines.append(f"\n[WHOIS]")
        for k, v in w.items():
            if v and k != 'raw':
                lines.append(f"  {k}: {v}")

    # Ports
    if 'open_ports' in data:
        lines.append(f"\n[OPEN PORTS]")
        for port, service, banner in data['open_ports']:
            lines.append(f"  {port}/tcp  {service}  {banner[:60] if banner else ''}")

    # Subdomains
    if 'subdomains' in data and data['subdomains']:
        lines.append(f"\n[SUBDOMAINS]")
        for full, ip in data['subdomains']:
            lines.append(f"  {full} -> {ip}")

    # Web
    if 'web' in data:
        w = data['web']
        lines.append(f"\n[WEB ANALYSIS]")
        if 'missing_security' in w:
            lines.append(f"  Missing security headers:")
            for h, d in w['missing_security']:
                lines.append(f"    - {h}: {d}")
        if 'info_disclosure' in w:
            lines.append(f"  Info disclosure headers:")
            for h, v, d in w['info_disclosure']:
                lines.append(f"    - {h}: {v}")

    # SSL
    if 'ssl' in data:
        s = data['ssl']
        lines.append(f"\n[SSL/TLS]")
        lines.append(f"  Issuer: {s.get('issuer', {}).get('organizationName', 'N/A')}")
        lines.append(f"  Expires: {s.get('not_after', 'N/A')}")
        lines.append(f"  Days Until Expiry: {s.get('days_until_expiry', 'N/A')}")

    # Vulns
    if 'vulnerabilities' in data and data['vulnerabilities']:
        lines.append(f"\n[VULNERABILITIES]")
        for v in data['vulnerabilities']:
            lines.append(f"  [{v['severity']}] {v['type']}")
            lines.append(f"    Parameter: {v.get('parameter', 'N/A')}")
            lines.append(f"    Evidence: {v.get('evidence', '')}")
            lines.append(f"    URL: {v.get('url', '')}")

    lines.append("\n" + "=" * 70)
    lines.append("END OF REPORT")

    report_text = "\n".join(lines)

    try:
        with open(output_path, 'w') as f:
            f.write(report_text)

        # Also save JSON
        json_path = output_path.replace('.txt', '.json')
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        return output_path, json_path
    except Exception as e:
        return None, str(e)