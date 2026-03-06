I made this tool because I like to get things done as swiftly as possible (especially tedious tasks like enumeration and footprinting). 

I always carry the words of my high school chemistry teacher who told me "lazy people find the most efficient way to do things".

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Unauthorized scanning
of computer systems is illegal under the Computer Fraud and Abuse Act (CFAA),
the Computer Misuse Act (UK), and similar laws worldwide.

**Always obtain explicit written permission before scanning any target.**

---

## Features

### Enumeration & Footprinting
- DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
- Reverse DNS lookup
- DNS zone transfer attempt (AXFR)
- Subdomain brute-force enumeration
- WHOIS domain registration info
- IP geolocation (via WHOIS)
- TCP port scanning (threaded, fast)
- Service banner grabbing
- SNMP UDP port check

### Deep Service Enumeration
Per-service results saved to `results/<target>/<service>/`.

| Service | Port | What's Checked |
|---------|------|----------------|
| **FTP** | 21 | Anonymous login, banner, directory listing, FEAT probe, nmap scripts |
| **SMB** | 139/445 | Null session, share enum, user enum, SMB signing, MS17-010 (EternalBlue), enum4linux |
| **SNMP** | 161/UDP | Community string brute-force (onesixtyone), snmpwalk (system/processes/network), nmap |
| **MySQL** | 3306 | Version banner, default creds, nmap scripts |
| **Oracle TNS** | 1521 | TNS version probe, SID brute-force, tnscmd10g |
| **SMTP** | 25/465/587 | Banner, EHLO commands, VRFY user enum, EXPN, open relay test, smtp-user-enum, nmap |
| **NFS** | 2049 | showmount export list, world-readable check, nmap nfs-ls |
| **DNS** | 53 | version.bind, recursion check, zone transfer (AXFR), nmap |
| **IMAP/POP3** | 143/110/993/995 | Banner, capabilities, STARTTLS check, nmap |
| **MSSQL** | 1433 | TDS banner/version, empty password, xp_cmdshell check, nmap |
| **IPMI** | 623/UDP | Version, Cipher Suite 0 vuln, RAKP hash capture, nmap |
| **HTTP/HTTPS** | 80/443/8080/8443 | whatweb, nikto, ffuf/dirb/gobuster directory brute-force |

### Web Analysis
- HTTP security header audit
- SSL/TLS certificate inspection
- Technology stack detection
- CMS fingerprinting (WordPress, Drupal, Joomla, etc.)
- Cookie security flag checks
- robots.txt parsing (reveals hidden paths)
- Common path/file discovery

### Vulnerability Checks
- Missing security headers
- Expired/expiring SSL certificates
- Sensitive file exposure (`.env`, `.git/config`, `phpinfo.php`, etc.)
- Directory listing detection
- CORS misconfiguration
- Dangerous HTTP methods (PUT, DELETE, TRACE)
- Clickjacking vulnerability
- *(Active mode)* Basic SQL injection error detection
- *(Active mode)* XSS reflection detection
- *(Active mode)* Open redirect detection

---

## Installation

```bash
# Clone or extract the tool
cd recon_tool

# Install dependencies
pip install -r requirements.txt
```

### Dependencies
- `dnspython` — Full DNS record resolution
- `python-whois` — WHOIS lookups
- `requests` — HTTP/HTTPS requests
- `colorama` — Colored terminal output

---

## Usage

```bash
# Basic scan (port scan + web checks + service enum)
python recon.py -t example.com

# Full scan (subdomains + active vuln checks)
python recon.py -t example.com --full

# Web-only scan (skip port scan and service enum)
python recon.py -t example.com --web-only

# Custom port range
python recon.py -t 192.168.1.1 --ports 1-65535

# Skip service enum (just port scan + web checks)
python recon.py -t example.com --skip-service-enum

# Save report to file
python recon.py -t example.com --output results.txt

# Skip legal prompt (for scripting)
python recon.py -t example.com -y

# Enable active vulnerability checks
python recon.py -t example.com --active
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `-t TARGET` | Target domain or IP (required) |
| `--full` | All checks: subdomains + active vulns |
| `--web-only` | Skip port scan and service enum |
| `--ports 1-1024` | Custom port range |
| `--no-subdomains` | Skip subdomain brute-force |
| `--skip-service-enum` | Skip FTP/SMB/SNMP/etc. deep enumeration |
| `--skip-vuln` | Skip web vulnerability checks |
| `--skip-whois` | Skip WHOIS lookup |
| `--active` | Enable active probes (SQLi, XSS, redirects) |
| `--no-banner` | Skip banner grabbing (faster scan) |
| `--output FILE` | Save report to .txt + .json |
| `--threads N` | Port scan thread count (default: 100) |
| `--timeout N` | HTTP timeout in seconds (default: 8) |
| `-y` | Skip legal disclaimer prompt |

---

## Output

Reports are saved in two formats:
- `report.txt` — Human-readable text report
- `report.json` — Machine-readable JSON for further processing

---

## Project Structure

```
recon_tool/
├── recon.py              # Main entry point
├── requirements.txt
├── README.md
├── modules/
│   ├── dns_enum.py       # DNS records & subdomain enum
│   ├── whois_lookup.py   # WHOIS & IP geolocation
│   ├── port_scanner.py   # TCP port scanner & banner grabber
│   ├── web_recon.py      # HTTP headers, SSL, CMS detection
│   ├── vuln_checks.py    # Vulnerability detection
│   ├── service_enum.py   # Deep per-service enumeration (FTP/SMB/SNMP/etc.)
│   └── reporter.py       # Terminal output & report generation
├── wordlists/
│   └── subdomains.txt    # Subdomain wordlist
└── results/              # Per-scan output (auto-created)
    └── <target>/
        ├── index.json    # Master findings index
        ├── ftp/
        ├── smb/
        ├── snmp/
        ├── smtp/
        ├── mysql/
        ├── mssql/
        ├── oracle/
        ├── nfs/
        ├── dns/
        ├── imap_pop3/
        ├── ipmi/
        └── http_80/
```

---

## External Tools (Optional but Recommended)

The tool works without these, but they significantly expand coverage. Install on Kali/Parrot/Ubuntu:

```bash
# Core
sudo apt install nmap enum4linux smbclient snmp snmp-mibs-downloader

# Web
sudo apt install nikto dirb whatweb gobuster
pip install ffuf  # or: go install github.com/ffuf/ffuf/v2@latest

# Service-specific
sudo apt install smtp-user-enum onesixtyone snmpwalk showmount

# Optional
sudo apt install tnscmd10g   # Oracle
pip install mysql-connector-python  # MySQL auth checks
```

If a tool isn't found, the module will fall back to Python-native probes.

---

## Extending the Tool

### Add custom vuln checks
Edit `modules/vuln_checks.py` and add a new function following the pattern:

```python
def check_my_vuln(base_url):
    findings = []
    # ... your logic ...
    findings.append({
        'type': 'My Vulnerability',
        'severity': 'HIGH',  # CRITICAL / HIGH / MEDIUM / LOW
        'parameter': 'param_name',
        'evidence': 'Description of what was found',
        'url': base_url,
    })
    return findings
```

Then register it in `run_all_checks()`.

### Add more subdomains
Append entries to `wordlists/subdomains.txt`.