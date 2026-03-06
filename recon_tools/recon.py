#!/usr/bin/env python3
"""
recon.py - Main Entry Point
Enumeration, Footprinting & Web Vulnerability Scanner

LEGAL DISCLAIMER:
This tool is intended for authorized security testing only.
Unauthorized scanning of systems is illegal and unethical.
Always obtain explicit written permission before scanning any target.
"""

import argparse
import sys
import os
import time
import datetime

# Add parent dir to path for module imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import reporter
from modules.reporter import section, subsection, item, success, warning, error, info
from colorama import Fore, Style


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════╗
║                    ⚠  LEGAL DISCLAIMER  ⚠                   ║
║                                                              ║
║  This tool is for AUTHORIZED security testing ONLY.         ║
║  Unauthorized scanning is illegal in most jurisdictions.    ║
║  You are responsible for ensuring you have explicit         ║
║  written permission to scan the target system.              ║
║                                                              ║
║  By continuing, you confirm you have authorization.         ║
╚══════════════════════════════════════════════════════════════╝
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog='recon.py',
        description='Enumeration, Footprinting & Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon.py -t example.com
  python recon.py -t example.com --full
  python recon.py -t 192.168.1.1 --ports 1-1024
  python recon.py -t example.com --web-only --output report.txt
  python recon.py -t example.com --skip-vuln --no-subdomains
        """
    )

    parser.add_argument('-t', '--target', required=True,
                        help='Target domain or IP address')
    parser.add_argument('--full', action='store_true',
                        help='Run all checks (subdomain enum + active vuln checks)')
    parser.add_argument('--web-only', action='store_true',
                        help='Only perform web checks (skip port scan)')
    parser.add_argument('--ports', default=None,
                        help='Port range to scan (e.g. 1-1024) or "common" (default)')
    parser.add_argument('--no-subdomains', action='store_true',
                        help='Skip subdomain enumeration')
    parser.add_argument('--skip-vuln', action='store_true',
                        help='Skip vulnerability checks')
    parser.add_argument('--skip-whois', action='store_true',
                        help='Skip WHOIS lookup')
    parser.add_argument('--skip-service-enum', action='store_true',
                        help='Skip deep per-service enumeration (FTP/SMB/SNMP/etc.)')
    parser.add_argument('--output', default=None,
                        help='Save report to file (e.g. report.txt)')
    parser.add_argument('--active', action='store_true',
                        help='Enable active vuln checks (SQLi probe, XSS reflection)')
    parser.add_argument('--no-banner', action='store_true',
                        help='Skip banner grabbing during port scan')
    parser.add_argument('-y', '--yes', action='store_true',
                        help='Skip legal disclaimer prompt')
    parser.add_argument('--threads', type=int, default=100,
                        help='Number of threads for port scanning (default: 100)')
    parser.add_argument('--timeout', type=int, default=8,
                        help='HTTP request timeout in seconds (default: 8)')

    return parser.parse_args()


def confirm_legal(yes=False):
    print(DISCLAIMER)
    if yes:
        return True
    ans = input("  Do you have authorization to scan this target? [y/N]: ").strip().lower()
    return ans == 'y'


def parse_port_range(ports_arg):
    if ports_arg is None or ports_arg.lower() == 'common':
        return None, None  # Use default common ports
    try:
        if '-' in ports_arg:
            start, end = ports_arg.split('-', 1)
            return int(start), int(end)
        else:
            p = int(ports_arg)
            return p, p
    except ValueError:
        print(f"[!] Invalid port range: {ports_arg}. Using common ports.")
        return None, None


def run_scan(args):
    target = args.target.strip().lower()
    # Remove http/https prefix if provided
    if target.startswith('http://') or target.startswith('https://'):
        from urllib.parse import urlparse
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    target = target.rstrip('/')

    scan_data = {
        'target': target,
        'scan_time': datetime.datetime.now().isoformat(),
        'vulnerabilities': [],
    }

    reporter.banner()
    print(f"\n  Target  : {target}")
    print(f"  Started : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── 1. DNS ENUMERATION ──────────────────────────────────────
    section("DNS Enumeration")
    from modules.dns_enum import resolve_host, get_dns_records, get_reverse_dns, enumerate_subdomains

    info(f"Resolving {target}...")
    ip = resolve_host(target)
    if ip:
        success(f"Resolved to: {ip}")
        scan_data['ip'] = ip

        reverse = get_reverse_dns(ip)
        if reverse:
            item("Reverse DNS", ', '.join(reverse))
            scan_data['reverse_dns'] = reverse
    else:
        error(f"Could not resolve {target}")
        scan_data['ip'] = None

    info("Fetching DNS records...")
    dns_records, dns_warnings = get_dns_records(target)
    scan_data['dns'] = dns_records

    reporter.print_dns_records(dns_records)
    for w in dns_warnings:
        warning(w)

    # Zone transfer attempt
    subsection("Zone Transfer Check (AXFR)")
    from modules.dns_enum import get_zone_transfer
    zt_results, zt_err = get_zone_transfer(target)
    if zt_results:
        warning(f"Zone transfer succeeded! {len(zt_results)} records exposed")
        for r in zt_results[:20]:
            print(f"      {r}")
        scan_data['zone_transfer'] = zt_results
    else:
        success("Zone transfer not allowed (expected)")
        scan_data['zone_transfer'] = []

    # Subdomain enumeration
    if args.full or not args.no_subdomains:
        subsection("Subdomain Enumeration")
        info("Brute-forcing subdomains (this may take a moment)...")
        subdomains, sub_err = enumerate_subdomains(target)
        scan_data['subdomains'] = subdomains
        if sub_err:
            warning(sub_err)
        elif subdomains:
            success(f"Found {len(subdomains)} subdomain(s):")
            reporter.print_subdomains(subdomains)
        else:
            info("No subdomains found")

    # ── 2. WHOIS ─────────────────────────────────────────────────
    if not args.skip_whois:
        section("WHOIS Lookup")
        from modules.whois_lookup import get_whois, get_ip_geolocation
        info("Querying WHOIS...")
        w = get_whois(target)
        scan_data['whois'] = w

        if w.get('error') and not w.get('raw'):
            error(f"WHOIS failed: {w['error']}")
        else:
            if w.get('registrar'): item("Registrar", w['registrar'])
            if w.get('org'):        item("Organization", w['org'])
            if w.get('country'):    item("Country", w['country'])
            if w.get('creation_date'): item("Created", str(w['creation_date']))
            if w.get('expiration_date'): item("Expires", str(w['expiration_date']))
            if w.get('name_servers'):
                item("Name Servers", ', '.join(str(x) for x in w['name_servers'][:4]))
            if w.get('emails'):
                item("Emails", ', '.join(str(x) for x in w['emails'][:3]))

        if ip:
            subsection("IP Geolocation (via WHOIS)")
            geo = get_ip_geolocation(ip)
            scan_data['geolocation'] = geo
            if geo.get('org'):     item("Organization", geo['org'])
            if geo.get('country'): item("Country", geo['country'])
            if geo.get('cidr'):    item("CIDR/Range", geo['cidr'])

    # ── 3. PORT SCAN ─────────────────────────────────────────────
    # Check SNMP (UDP) regardless of web_only mode
    snmp_open = False

    if not args.web_only and ip:
        section("Port Scanning")
        from modules.port_scanner import scan_ports, COMMON_PORTS, detect_web_services

        port_start, port_end = parse_port_range(args.ports)
        if port_start and port_end:
            info(f"Scanning ports {port_start}-{port_end} on {ip}...")
            port_range = (port_start, port_end)
            ports_arg = None
        else:
            info(f"Scanning {len(COMMON_PORTS)} common ports on {ip}...")
            port_range = None
            ports_arg = COMMON_PORTS

        start_time = time.time()
        open_ports = scan_ports(
            ip,
            ports=ports_arg,
            port_range=port_range,
            max_workers=args.threads,
            grab_banners=not args.no_banner
        )
        elapsed = time.time() - start_time
        scan_data['open_ports'] = open_ports

        success(f"Scan complete in {elapsed:.1f}s — {len(open_ports)} open port(s)")
        reporter.print_open_ports(open_ports)

        web_services = detect_web_services(open_ports)
        scan_data['web_services'] = web_services

        # Check SNMP (UDP) separately since port scanner is TCP-only
        from modules.service_enum import check_snmp_udp
        info("Checking SNMP (UDP/161)...")
        snmp_open = check_snmp_udp(ip)
        if snmp_open:
            warning("SNMP port 161/UDP is OPEN")
            # Add a synthetic entry so service_enum picks it up
            open_ports_with_snmp = list(open_ports) + [(161, 'SNMP', '')]
            scan_data['open_ports'] = open_ports_with_snmp
        else:
            info("SNMP (UDP/161) not responding")

    else:
        # Try default HTTP/HTTPS
        web_services = [(443, 'https'), (80, 'http')]
        scan_data['open_ports'] = []
        scan_data['web_services'] = web_services

    # ── 3b. DEEP SERVICE ENUMERATION ─────────────────────────────
    if not args.web_only and scan_data.get('open_ports') and not args.skip_service_enum:
        section("Deep Service Enumeration")

        from modules.service_enum import run_service_enum

        results_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'results',
            target.replace('/', '_')
        )
        os.makedirs(results_dir, exist_ok=True)
        info(f"Results directory: {results_dir}")

        def svc_progress(svc_name, status):
            info(f"[{svc_name}] {status}")

        svc_results = run_service_enum(
            ip or target,
            scan_data['open_ports'],
            results_dir,
            domain=target if '.' in target else None,
            progress_cb=svc_progress
        )
        scan_data['service_enum'] = svc_results

        # Print findings summary
        subsection("Service Enumeration Findings")
        total_findings = 0
        for svc, res in svc_results.items():
            if isinstance(res, dict) and res.get('findings'):
                print(f"\n    {Fore.CYAN}{svc.upper()}{Style.RESET_ALL}")
                for finding in res['findings']:
                    sev_color = Fore.RED if any(x in finding.upper() for x in ['CRITICAL', 'ANONYMOUS', 'RELAY', 'VULNERABLE', 'DISABLED']) else \
                                Fore.YELLOW if any(x in finding.upper() for x in ['WARNING', 'OPEN', 'ENABLED', 'FOUND']) else Fore.WHITE
                    print(f"      {sev_color}→ {finding}{Style.RESET_ALL}")
                    total_findings += 1

        success(f"Service enum complete — {total_findings} finding(s) across {len(svc_results)} service(s)")
        success(f"Per-service files saved to: {results_dir}")

    # ── 4. SERVICE ENUMERATION ──────────────────────────────────
    if not args.skip_service_enum and scan_data.get('open_ports'):
        section("Deep Service Enumeration")
        from modules.service_enum import run_service_enum, SERVICE_DESCRIPTIONS

        results_base = os.path.dirname(os.path.abspath(__file__))
        if args.output:
            results_base = os.path.dirname(os.path.abspath(args.output))

        info(f"Launching per-service enumerators (this may take several minutes)...")
        info(f"Results saved to: {os.path.join(results_base, 'results', '<service>')}/")
        print()

        def svc_callback(port, svc_name, status, result):
            desc = SERVICE_DESCRIPTIONS.get(svc_name, svc_name.upper())
            if status == 'ok':
                success(f"[{port}/tcp] {svc_name.upper():<8} — {desc}")
                if isinstance(result, dict):
                    # Highlight key findings inline
                    if result.get('anonymous_login'):
                        warning(f"         FTP anonymous login OPEN")
                    if result.get('open_relay'):
                        warning(f"         SMTP open relay detected!")
                    if result.get('eternalblue'):
                        error(f"          MS17-010 EternalBlue VULNERABLE!")
                    if result.get('cipher0_bypass'):
                        error(f"          IPMI Cipher 0 bypass possible!")
                    if result.get('valid_creds'):
                        for u, p in result['valid_creds']:
                            warning(f"         Default creds valid: {u}:{p or '(empty)'}")
                    if result.get('community_strings'):
                        warning(f"         SNMP community strings: {', '.join(result['community_strings'])}")
            else:
                error(f"[{port}/tcp] {svc_name.upper():<8} — ERROR: {result}")

        svc_results = run_service_enum(
            target=ip or target,
            open_ports=scan_data['open_ports'],
            results_base=results_base,
            max_workers=3,
            callback=svc_callback,
        )
        scan_data['service_enum'] = svc_results

        # Summary of results files
        results_dir = os.path.join(results_base, 'results')
        if os.path.exists(results_dir):
            print()
            info(f"Enumeration output files:")
            for svc_dir in sorted(os.listdir(results_dir)):
                full = os.path.join(results_dir, svc_dir)
                if os.path.isdir(full):
                    files = os.listdir(full)
                    print(f"    results/{svc_dir}/  ({len(files)} file(s))")

    # ── 5. WEB ANALYSIS ─────────────────────────────────────────
    from modules.web_recon import (
        make_request, analyze_headers, get_ssl_info, check_paths,
        detect_cms, fetch_robots_txt, check_clickjacking, detect_technologies
    )

    # Determine base URL
    base_url = None
    if web_services:
        for port, scheme in web_services:
            test_url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"
            resp, err = make_request(test_url, timeout=args.timeout)
            if resp:
                base_url = test_url
                break

    if not base_url:
        # Try direct
        for scheme, port in [('https', 443), ('http', 80)]:
            test_url = f"{scheme}://{target}"
            resp, err = make_request(test_url, timeout=args.timeout)
            if resp:
                base_url = test_url
                break

    if base_url:
        section(f"Web Analysis — {base_url}")
        resp, err = make_request(base_url, timeout=args.timeout)

        if err:
            error(f"Web request failed: {err}")
        else:
            success(f"HTTP {resp.status_code} — {len(resp.content)} bytes")

            # Headers
            subsection("HTTP Security Headers")
            header_analysis = analyze_headers(resp)
            scan_data['web'] = header_analysis

            if header_analysis['info_disclosure']:
                warning("Information disclosure via headers:")
                for h, v, d in header_analysis['info_disclosure']:
                    print(f"    {h}: {v}  ({d})")

            if header_analysis['missing_security']:
                warning(f"{len(header_analysis['missing_security'])} missing security header(s):")
                for h, d in header_analysis['missing_security']:
                    print(f"    ✗ {h} — {d}")
            else:
                success("All major security headers present")

            if header_analysis['present_security']:
                info(f"{len(header_analysis['present_security'])} security header(s) present:")
                for h, v, d in header_analysis['present_security']:
                    print(f"    ✓ {h}")

            # Cookie analysis
            if header_analysis.get('cookie_issues'):
                warning("Cookie security issues:")
                for issue in header_analysis['cookie_issues']:
                    print(f"    - {issue}")

            # Technologies
            subsection("Technology Detection")
            tech = detect_technologies(resp)
            scan_data['technologies'] = tech
            if tech:
                for t in tech:
                    info(t)
            else:
                info("No specific technologies detected from headers/body")

            # CMS Detection
            subsection("CMS Detection")
            cms = detect_cms(base_url, resp.text)
            scan_data['cms'] = cms
            if cms:
                warning(f"Detected CMS: {', '.join(cms)}")
            else:
                info("No known CMS detected")

            # Clickjacking
            subsection("Clickjacking Check")
            is_vuln, msg = check_clickjacking(resp)
            if is_vuln:
                warning(msg)
                scan_data['vulnerabilities'].append({
                    'type': 'Clickjacking',
                    'severity': 'MEDIUM',
                    'parameter': 'N/A',
                    'evidence': msg,
                    'url': base_url,
                })
            else:
                success(msg)

            # SSL/TLS
            if base_url.startswith('https'):
                subsection("SSL/TLS Certificate")
                ssl_info = get_ssl_info(target)
                scan_data['ssl'] = ssl_info

                if ssl_info.get('error'):
                    error(f"SSL error: {ssl_info['error']}")
                else:
                    item("Protocol", ssl_info.get('version', 'N/A'))
                    issuer = ssl_info.get('issuer', {}).get('organizationName', 'Unknown')
                    item("Issuer", issuer)
                    item("Expires", ssl_info.get('not_after', 'N/A'))

                    days = ssl_info.get('days_until_expiry')
                    if days is not None:
                        if days < 0:
                            error(f"Certificate EXPIRED {abs(days)} days ago!")
                            scan_data['vulnerabilities'].append({
                                'type': 'Expired SSL Certificate',
                                'severity': 'CRITICAL',
                                'parameter': 'N/A',
                                'evidence': f"Certificate expired {abs(days)} days ago",
                                'url': base_url,
                            })
                        elif days < 30:
                            warning(f"Certificate expires in {days} days!")
                        else:
                            success(f"Certificate valid for {days} more days")

                    san = ssl_info.get('san', [])
                    if san:
                        item("SANs", ', '.join(san[:6]))

            # Robots.txt
            subsection("robots.txt Analysis")
            robots_text, disallowed = fetch_robots_txt(base_url)
            if robots_text:
                success("Found robots.txt")
                if disallowed:
                    info(f"{len(disallowed)} disallowed path(s) (interesting targets):")
                    for p in disallowed[:15]:
                        print(f"    {p}")
                scan_data['robots_disallowed'] = disallowed
            else:
                info("No robots.txt found")

            # Path discovery
            subsection("Common Path Discovery")
            info("Checking for sensitive paths and files...")
            found_paths = check_paths(base_url)
            scan_data['found_paths'] = found_paths
            if found_paths:
                warning(f"{len(found_paths)} interesting path(s) found:")
                reporter.print_paths(found_paths)
            else:
                success("No sensitive paths found")

            # ── 6. VULNERABILITY CHECKS ─────────────────────────
            if not args.skip_vuln:
                section("Vulnerability Checks")
                from modules.vuln_checks import run_all_checks

                info("Running vulnerability checks...")
                enable_active = args.active or args.full
                if enable_active:
                    warning("Active checks enabled (SQLi probes, XSS reflection)")

                vuln_findings = run_all_checks(base_url, enable_active=enable_active)
                scan_data['vulnerabilities'].extend(vuln_findings)

                if vuln_findings:
                    warning(f"{len(vuln_findings)} potential vulnerability/issue(s) found:")
                    for finding in vuln_findings:
                        reporter.vuln(finding)
                else:
                    success("No automated vulnerabilities detected")

                # Print full vuln summary
                all_vulns = scan_data['vulnerabilities']
                if all_vulns:
                    section("Vulnerability Summary")
                    crit = [v for v in all_vulns if v['severity'] == 'CRITICAL']
                    high = [v for v in all_vulns if v['severity'] == 'HIGH']
                    med  = [v for v in all_vulns if v['severity'] == 'MEDIUM']
                    low  = [v for v in all_vulns if v['severity'] == 'LOW']

                    from colorama import Fore, Style
                    if crit: print(f"    {Fore.RED}{Style.BRIGHT}CRITICAL : {len(crit)}{Style.RESET_ALL}")
                    if high:  print(f"    {Fore.RED}HIGH     : {len(high)}{Style.RESET_ALL}")
                    if med:   print(f"    {Fore.YELLOW}MEDIUM   : {len(med)}{Style.RESET_ALL}")
                    if low:   print(f"    {Fore.CYAN}LOW      : {len(low)}{Style.RESET_ALL}")
    else:
        warning(f"No web service accessible on {target}")
        scan_data['web'] = None

    # ── 7. REPORT ────────────────────────────────────────────────
    section("Scan Complete")
    print(f"\n  Target  : {target}")
    print(f"  Finished: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Open Ports: {len(scan_data.get('open_ports', []))}")
    print(f"  Subdomains: {len(scan_data.get('subdomains', []))}")
    print(f"  Vulnerabilities: {len(scan_data.get('vulnerabilities', []))}")

    if args.output:
        out_path = args.output if args.output.endswith('.txt') else args.output + '.txt'
        txt, json_path = reporter.generate_report(scan_data, out_path)
        if txt:
            success(f"Report saved: {txt}")
            success(f"JSON report : {json_path}")
        else:
            error(f"Failed to save report: {json_path}")
    else:
        info("Tip: Use --output report.txt to save results")

    print()
    return scan_data


def main():
    args = parse_args()

    if not confirm_legal(args.yes):
        print("\n  Exiting. Only scan systems you are authorized to test.\n")
        sys.exit(0)

    try:
        run_scan(args)
    except KeyboardInterrupt:
        print("\n\n  [!] Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n  [!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()