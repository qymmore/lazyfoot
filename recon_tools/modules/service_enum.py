"""
service_enum.py - Deep Per-Service Enumeration Module

Performs targeted enumeration for each discovered open service.
For each service, results are saved to results/<service>/ subdirectory.

Supported services:
  FTP (21), SSH (22), SMTP (25/465/587), DNS (53), HTTP/S (80/443/8080/8443),
  IMAP (143/993), SNMP (161 UDP), MSSQL (1433), MySQL (3306),
  Oracle TNS (1521), NFS (2049), SMB (139/445), IPMI (623 UDP),
  POP3 (110/995)

NOTE: For authorized security testing only.
"""

import os
import re
import socket
import ftplib
import imaplib
import poplib
import smtplib
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _write(path, content):
    """Append content to a file, creating parent dirs as needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a', encoding='utf-8', errors='replace') as f:
        f.write(content + '\n')


def _header(service, target, port):
    return (
        f"{'='*60}\n"
        f"  SERVICE : {service.upper()}\n"
        f"  TARGET  : {target}:{port}\n"
        f"  TIME    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'='*60}\n"
    )


def _run_tool(cmd, timeout=30):
    """
    Run an external tool if available on PATH.
    Returns (stdout, stderr, returncode).
    """
    tool = cmd[0]
    which = subprocess.run(['which', tool], capture_output=True)
    if which.returncode != 0:
        return None, f"Tool '{tool}' not found in PATH", -1
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors='replace')
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return None, f"Timeout after {timeout}s", -1
    except Exception as e:
        return None, str(e), -1


def _nmap(target, port, scripts, extra_args=None, timeout=60):
    """Run nmap with specified NSE scripts against target:port."""
    cmd = ['nmap', '-sV', '--open', '-p', str(port),
           '--script', scripts, target]
    if extra_args:
        cmd.extend(extra_args)
    return _run_tool(cmd, timeout=timeout)


def make_results_dir(base_dir, service_name):
    """Create and return path to results/<service>/ directory."""
    path = os.path.join(base_dir, 'results', service_name)
    os.makedirs(path, exist_ok=True)
    return path


# ─────────────────────────────────────────────────────────────
# FTP — Port 21
# ─────────────────────────────────────────────────────────────

def enum_ftp(target, port, results_base):
    """
    FTP enumeration:
    - Banner grabbing (raw socket)
    - Anonymous login attempt
    - Directory listing if anon succeeds
    - Common subdirectory crawl
    - nmap ftp scripts (anon, bounce, syst, vsftpd backdoor)
    """
    out = {}
    rdir = make_results_dir(results_base, 'ftp')
    outfile = os.path.join(rdir, 'ftp_enum.txt')
    _write(outfile, _header('FTP', target, port))

    # 1. Raw banner
    try:
        s = socket.create_connection((target, port), timeout=5)
        banner = s.recv(1024).decode(errors='replace').strip()
        s.close()
        out['banner'] = banner
        _write(outfile, f"[BANNER]\n{banner}\n")
    except Exception as e:
        out['banner'] = None
        _write(outfile, f"[BANNER] Failed: {e}\n")

    # 2. Anonymous login
    anon_success = False
    anon_files = []
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=8)
        ftp.login('anonymous', 'anonymous@test.com')
        anon_success = True
        _write(outfile, "\n[ANONYMOUS LOGIN] SUCCESS\n")

        # Root listing
        try:
            lines = []
            ftp.retrlines('LIST', lines.append)
            anon_files = lines
            _write(outfile, "\n[DIRECTORY LISTING — ROOT]\n" + '\n'.join(lines))
        except Exception:
            pass

        # Common sub-dirs
        for d in ['pub', 'share', 'uploads', 'files', 'backup', 'data', 'www']:
            try:
                ftp.cwd(d)
                sub = []
                ftp.retrlines('LIST', sub.append)
                if sub:
                    _write(outfile, f"\n[DIR: /{d}]\n" + '\n'.join(sub))
                    anon_files.extend([f"/{d}/{l}" for l in sub])
                ftp.cwd('/')
            except Exception:
                pass

        ftp.quit()
    except ftplib.error_perm as e:
        _write(outfile, f"\n[ANONYMOUS LOGIN] DENIED — {e}\n")
    except Exception as e:
        _write(outfile, f"\n[ANONYMOUS LOGIN] Error — {e}\n")

    out['anonymous_login'] = anon_success
    out['files'] = anon_files

    # 3. nmap scripts
    stdout, _, _ = _nmap(target, port,
        'ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor')
    if stdout:
        _write(outfile, f"\n[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout

    return out


# ─────────────────────────────────────────────────────────────
# SSH — Port 22
# ─────────────────────────────────────────────────────────────

def enum_ssh(target, port, results_base):
    """
    SSH enumeration:
    - Banner / protocol version grabbing
    - Supported authentication methods
    - Host key fingerprints
    - Algorithm enumeration
    - nmap ssh scripts
    """
    out = {}
    rdir = make_results_dir(results_base, 'ssh')
    outfile = os.path.join(rdir, 'ssh_enum.txt')
    _write(outfile, _header('SSH', target, port))

    # Raw banner
    try:
        s = socket.create_connection((target, port), timeout=5)
        banner = s.recv(256).decode(errors='replace').strip()
        s.close()
        out['banner'] = banner
        _write(outfile, f"[BANNER]\n{banner}\n")
    except Exception as e:
        out['banner'] = None
        _write(outfile, f"[BANNER] Failed: {e}\n")

    # nmap ssh scripts
    stdout, _, _ = _nmap(target, port,
        'ssh-auth-methods,ssh-hostkey,ssh2-enum-algos')
    if stdout:
        _write(outfile, f"\n[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout

    return out


# ─────────────────────────────────────────────────────────────
# SMTP — Ports 25, 465, 587
# ─────────────────────────────────────────────────────────────

SMTP_USER_LIST = [
    'root', 'admin', 'administrator', 'postmaster', 'mail',
    'webmaster', 'info', 'test', 'guest', 'ftp', 'backup',
    'support', 'security', 'hostmaster', 'abuse', 'noreply',
    'user', 'sales', 'marketing', 'hr', 'finance',
]


def enum_smtp(target, port, results_base):
    """
    SMTP enumeration:
    - Banner grabbing + EHLO handshake
    - Supported ESMTP extensions
    - STARTTLS detection
    - User enumeration via VRFY and EXPN
    - Open relay test
    - nmap smtp scripts (commands, user enum, open relay, ntlm-info)
    - smtp-user-enum tool (if installed)
    """
    out = {'banner': None, 'extensions': [], 'users': [], 'starttls': False}
    rdir = make_results_dir(results_base, 'smtp')
    outfile = os.path.join(rdir, 'smtp_enum.txt')
    _write(outfile, _header('SMTP', target, port))

    # 1. Banner + EHLO
    try:
        smtp = smtplib.SMTP(timeout=8)
        smtp.connect(target, port)
        banner = smtp.getwelcome().decode(errors='replace')
        out['banner'] = banner
        _write(outfile, f"[BANNER]\n{banner}\n")

        code, resp = smtp.ehlo('recon.test')
        exts = resp.decode(errors='replace')
        out['extensions'] = exts.splitlines()
        _write(outfile, f"\n[EHLO EXTENSIONS]\n{exts}\n")

        if 'STARTTLS' in exts.upper():
            out['starttls'] = True
            _write(outfile, "[+] STARTTLS supported\n")

        # 2. VRFY user enum
        found_users = []
        _write(outfile, "\n[VRFY USER ENUMERATION]\n")
        for user in SMTP_USER_LIST:
            try:
                code, msg = smtp.verify(user)
                line = f"  {user}: {code} {msg.decode(errors='replace')}"
                _write(outfile, line)
                if code in (250, 251, 252):
                    found_users.append(user)
            except Exception:
                pass

        # 3. EXPN
        _write(outfile, "\n[EXPN]\n")
        for user in ['admin', 'root', 'postmaster']:
            try:
                code, msg = smtp.expn(user)
                _write(outfile, f"  {user}: {code} {msg.decode(errors='replace')}")
            except Exception:
                pass

        # 4. Open relay test
        _write(outfile, "\n[OPEN RELAY TEST]\n")
        try:
            smtp.mail('test@test.com')
            code, msg = smtp.rcpt('relaytest@external-domain.com')
            if code == 250:
                _write(outfile, "  [!!!] OPEN RELAY DETECTED — server accepted external recipient\n")
                out['open_relay'] = True
            else:
                _write(outfile, f"  [-] Relay rejected: {code}\n")
        except Exception:
            pass

        out['users'] = found_users
        smtp.quit()

    except Exception as e:
        _write(outfile, f"[ERROR] SMTP connection: {e}\n")

    # 5. nmap scripts
    stdout, _, _ = _nmap(target, port,
        'smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-open-relay')
    if stdout:
        _write(outfile, f"\n[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout

    # 6. smtp-user-enum tool
    wordlists = [
        '/usr/share/wordlists/metasploit/unix_users.txt',
        '/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
    ]
    wl = next((w for w in wordlists if os.path.exists(w)), None)
    if wl:
        stdout, _, _ = _run_tool(
            ['smtp-user-enum', '-M', 'VRFY', '-U', wl,
             '-t', target, '-p', str(port)], timeout=60)
        if stdout:
            _write(outfile, f"\n[smtp-user-enum TOOL]\n{stdout}")
            out['smtp_user_enum_tool'] = stdout

    return out


# ─────────────────────────────────────────────────────────────
# DNS — Port 53
# ─────────────────────────────────────────────────────────────

def enum_dns(target, port, results_base):
    """
    DNS service enumeration:
    - Version bind query
    - Recursion check
    - Zone transfer attempts
    - Cache snooping
    - nmap dns scripts
    """
    out = {}
    rdir = make_results_dir(results_base, 'dns')
    outfile = os.path.join(rdir, 'dns_enum.txt')
    _write(outfile, _header('DNS', target, port))

    # nmap dns scripts (both TCP and UDP)
    stdout, _, _ = _nmap(target, port,
        'dns-recursion,dns-cache-snoop,dns-zone-transfer,dns-srv-enum,dns-nsid')
    if stdout:
        _write(outfile, f"[NMAP SCRIPTS — TCP]\n{stdout}")
        out['nmap_tcp'] = stdout

    # dig version.bind
    stdout, _, _ = _run_tool(
        ['dig', f'@{target}', '-p', str(port), 'version.bind', 'txt', 'chaos'])
    if stdout:
        _write(outfile, f"\n[DIG VERSION.BIND]\n{stdout}")
        out['version_bind'] = stdout

    # dig AXFR
    stdout, _, _ = _run_tool(
        ['dig', f'@{target}', '-p', str(port), 'axfr', target])
    if stdout:
        _write(outfile, f"\n[DIG AXFR]\n{stdout}")
        out['axfr'] = stdout

    # dnsrecon
    stdout, _, _ = _run_tool(
        ['dnsrecon', '-d', target, '-n', target, '-t', 'axfr'], timeout=30)
    if stdout:
        _write(outfile, f"\n[dnsrecon]\n{stdout}")
        out['dnsrecon'] = stdout

    return out


# ─────────────────────────────────────────────────────────────
# SNMP — Port 161 (UDP)
# ─────────────────────────────────────────────────────────────

SNMP_COMMUNITY_STRINGS = [
    'public', 'private', 'community', 'manager', 'admin',
    'cisco', 'router', 'switch', 'monitor', 'write',
    'read', 'snmp', 'network', 'default', '0', '1234',
]

SNMP_OIDS = {
    'sysDescr':    '1.3.6.1.2.1.1.1.0',
    'sysName':     '1.3.6.1.2.1.1.5.0',
    'sysLocation': '1.3.6.1.2.1.1.6.0',
    'sysContact':  '1.3.6.1.2.1.1.4.0',
    'sysUpTime':   '1.3.6.1.2.1.1.3.0',
}


def _snmp_get_raw(target, port, community, oid, timeout=2):
    """Minimal pure-Python SNMPv1 GET to probe community string validity."""
    def enc_oid(s):
        parts = list(map(int, s.split('.')))
        b = bytes([40 * parts[0] + parts[1]])
        for p in parts[2:]:
            if p == 0:
                b += b'\x00'
            else:
                enc = []
                while p:
                    enc.append(p & 0x7f)
                    p >>= 7
                enc.reverse()
                b += bytes([x | (0x80 if i < len(enc)-1 else 0)
                            for i, x in enumerate(enc)])
        return b'\x06' + bytes([len(b)]) + b

    def tlv(tag, val):
        return bytes([tag, len(val)]) + val

    oid_enc = enc_oid(oid)
    vbind = tlv(0x30, oid_enc + b'\x05\x00')
    pdu = tlv(0xa0,
        tlv(0x02, b'\x01') + tlv(0x02, b'\x00') +
        tlv(0x02, b'\x00') + tlv(0x30, vbind))
    pkt = tlv(0x30,
        tlv(0x02, b'\x00') + tlv(0x04, community.encode()) + pdu)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (target, port))
        data, _ = s.recvfrom(4096)
        s.close()
        strings = re.findall(b'[\x20-\x7e]{4,}', data)
        return [x.decode('ascii', errors='replace') for x in strings]
    except Exception:
        return None


def enum_snmp(target, port, results_base):
    """
    SNMP enumeration:
    - Community string brute-force (native Python + onesixtyone)
    - System info via OID walk for valid communities
    - snmpwalk output (if installed)
    - nmap snmp scripts
    """
    out = {'community_strings': [], 'info': {}}
    rdir = make_results_dir(results_base, 'snmp')
    outfile = os.path.join(rdir, 'snmp_enum.txt')
    _write(outfile, _header('SNMP', target, port))

    # 1. Community string brute-force (native)
    _write(outfile, "[COMMUNITY STRING BRUTEFORCE — native]\n")
    valid = []
    for comm in SNMP_COMMUNITY_STRINGS:
        result = _snmp_get_raw(target, port, comm, SNMP_OIDS['sysDescr'])
        if result:
            valid.append(comm)
            _write(outfile, f"  [+] VALID: '{comm}'  →  {result[0][:80]}")
    out['community_strings'] = valid

    # 2. onesixtyone
    wl_candidates = [
        '/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt',
        '/usr/share/wordlists/metasploit/snmp_default_pass.txt',
    ]
    wl = next((w for w in wl_candidates if os.path.exists(w)), None)
    if wl:
        stdout, _, _ = _run_tool(['onesixtyone', '-c', wl, target], timeout=30)
        if stdout:
            _write(outfile, f"\n[onesixtyone]\n{stdout}")
            out['onesixtyone'] = stdout

    # 3. snmpwalk for each valid community
    for comm in valid[:2]:
        _write(outfile, f"\n[snmpwalk — community: '{comm}']\n")
        stdout, _, rc = _run_tool(
            ['snmpwalk', '-v1', '-c', comm, '-OeQn', target], timeout=30)
        if stdout:
            _write(outfile, stdout[:6000])
            out['snmpwalk'] = stdout[:6000]
        else:
            # Fallback: query key OIDs natively
            _write(outfile, "[snmpwalk not available — querying key OIDs natively]\n")
            for name, oid in SNMP_OIDS.items():
                r = _snmp_get_raw(target, port, comm, oid)
                if r:
                    _write(outfile, f"  {name}: {' | '.join(r[:2])}")
                    out['info'][name] = r[:2]

    # 4. nmap scripts
    stdout, _, _ = _nmap(target, port,
        'snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,'
        'snmp-sysdescr,snmp-win32-users,snmp-win32-software',
        extra_args=['-sU'], timeout=60)
    if stdout:
        _write(outfile, f"\n[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout

    return out


# ─────────────────────────────────────────────────────────────
# SMB — Ports 139, 445
# ─────────────────────────────────────────────────────────────

def enum_smb(target, port, results_base):
    """
    SMB enumeration:
    - OS discovery, signing, dialect
    - Share enumeration (null session)
    - User enumeration
    - EternalBlue / MS17-010 check
    - nmap smb scripts
    - enum4linux
    - smbclient null session
    - CrackMapExec
    """
    out = {}
    rdir = make_results_dir(results_base, 'smb')
    outfile = os.path.join(rdir, 'smb_enum.txt')
    _write(outfile, _header('SMB', target, port))

    # 1. nmap smb scripts
    scripts = (
        'smb-enum-shares,smb-enum-users,smb-os-discovery,'
        'smb-security-mode,smb2-security-mode,smb-vuln-ms17-010,'
        'smb-vuln-ms08-067,smb-system-info,smb-protocols,'
        'smb-vuln-cve-2017-7494'
    )
    stdout, _, _ = _nmap(target, port, scripts, timeout=120)
    if stdout:
        _write(outfile, f"[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout
        if 'VULNERABLE' in stdout and 'MS17-010' in stdout:
            out['eternalblue'] = True
            _write(outfile, "\n[!!!] MS17-010 (EternalBlue) — VULNERABLE\n")

    # 2. smbclient null session share listing
    stdout, _, _ = _run_tool(
        ['smbclient', '-L', f'//{target}', '-N',
         '--option=client min protocol=NT1'], timeout=20)
    if stdout:
        _write(outfile, f"\n[smbclient NULL SESSION]\n{stdout}")
        out['smbclient'] = stdout

    # 3. enum4linux
    stdout, _, _ = _run_tool(['enum4linux', '-a', target], timeout=180)
    if stdout:
        _write(outfile, f"\n[enum4linux]\n{stdout[:10000]}")
        out['enum4linux'] = stdout[:10000]

    # 4. CrackMapExec
    stdout, _, _ = _run_tool(['crackmapexec', 'smb', target], timeout=30)
    if stdout:
        _write(outfile, f"\n[CrackMapExec]\n{stdout}")
        out['cme'] = stdout

    return out


# ─────────────────────────────────────────────────────────────
# NFS — Port 2049
# ─────────────────────────────────────────────────────────────

def enum_nfs(target, port, results_base):
    """
    NFS enumeration:
    - showmount exports listing
    - rpcinfo registered RPC services
    - nmap nfs scripts
    """
    out = {}
    rdir = make_results_dir(results_base, 'nfs')
    outfile = os.path.join(rdir, 'nfs_enum.txt')
    _write(outfile, _header('NFS', target, port))

    # showmount
    stdout, _, _ = _run_tool(['showmount', '-e', target], timeout=15)
    if stdout:
        _write(outfile, f"[EXPORTS — showmount]\n{stdout}")
        out['exports'] = stdout

    # rpcinfo
    stdout, _, _ = _run_tool(['rpcinfo', '-p', target], timeout=10)
    if stdout:
        _write(outfile, f"\n[rpcinfo]\n{stdout}")
        out['rpcinfo'] = stdout

    # nmap nfs scripts
    stdout, _, _ = _nmap(target, port,
        'nfs-showmount,nfs-ls,nfs-statfs,rpcinfo')
    if stdout:
        _write(outfile, f"\n[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout

    return out


# ─────────────────────────────────────────────────────────────
# MySQL — Port 3306
# ─────────────────────────────────────────────────────────────

MYSQL_DEFAULT_CREDS = [
    ('root', ''), ('root', 'root'), ('root', 'toor'),
    ('root', 'password'), ('root', 'mysql'), ('admin', 'admin'),
    ('mysql', 'mysql'),
]


def _mysql_banner(target, port, timeout=5):
    """Grab MySQL server greeting banner via raw socket."""
    try:
        s = socket.create_connection((target, port), timeout=timeout)
        data = s.recv(256)
        s.close()
        if len(data) > 5:
            rest = data[5:]
            idx = rest.find(b'\x00')
            if idx > 0:
                return rest[:idx].decode(errors='replace')
    except Exception:
        pass
    return None


def enum_mysql(target, port, results_base):
    """
    MySQL enumeration:
    - Banner/version detection
    - Default credential testing (mysql CLI + nmap)
    - Database/user listing on successful login
    - nmap mysql scripts
    """
    out = {}
    rdir = make_results_dir(results_base, 'mysql')
    outfile = os.path.join(rdir, 'mysql_enum.txt')
    _write(outfile, _header('MySQL', target, port))

    version = _mysql_banner(target, port)
    if version:
        out['version'] = version
        _write(outfile, f"[BANNER] MySQL {version}\n")

    # nmap scripts
    stdout, _, _ = _nmap(target, port,
        'mysql-info,mysql-empty-password,mysql-enum,mysql-databases,mysql-users')
    if stdout:
        _write(outfile, f"\n[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout

    # Default credential testing
    _write(outfile, "\n[DEFAULT CREDENTIAL TEST]\n")
    valid_creds = []
    for user, pwd in MYSQL_DEFAULT_CREDS:
        cmd = ['mysql', '-h', target, '-P', str(port),
               f'-u{user}', f'-p{pwd}',
               '-e', 'SELECT user,host FROM mysql.user LIMIT 10;',
               '--connect-timeout=5', '--batch', '--silent']
        stdout_c, _, rc = _run_tool(cmd, timeout=12)
        if rc == 0 and stdout_c:
            valid_creds.append((user, pwd))
            _write(outfile, f"  [+] VALID: {user}:{pwd or '(empty)'}")
            _write(outfile, f"      {stdout_c[:500]}")
            # Also dump databases
            db_cmd = cmd[:-2] + ['-e', 'SHOW DATABASES;']
            db_out, _, _ = _run_tool(db_cmd, timeout=10)
            if db_out:
                _write(outfile, f"\n  [DATABASES]\n{db_out}")
        else:
            _write(outfile, f"  [-] {user}:{pwd or '(empty)'}")

    out['valid_creds'] = valid_creds
    return out


# ─────────────────────────────────────────────────────────────
# MSSQL — Port 1433
# ─────────────────────────────────────────────────────────────

MSSQL_DEFAULT_CREDS = [
    ('sa', ''), ('sa', 'sa'), ('sa', 'password'),
    ('sa', 'admin'), ('admin', 'admin'), ('sa', 'Password1'),
]


def enum_mssql(target, port, results_base):
    """
    MSSQL enumeration:
    - Version/config via nmap scripts
    - Default SA credential testing
    - NTLM info disclosure
    - xp_cmdshell status check
    - CrackMapExec mssql
    """
    out = {}
    rdir = make_results_dir(results_base, 'mssql')
    outfile = os.path.join(rdir, 'mssql_enum.txt')
    _write(outfile, _header('MSSQL', target, port))

    # nmap scripts
    stdout, _, _ = _nmap(target, port,
        'ms-sql-info,ms-sql-config,ms-sql-empty-password,'
        'ms-sql-ntlm-info,ms-sql-tables,ms-sql-xp-cmdshell',
        timeout=90)
    if stdout:
        _write(outfile, f"[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout

    # sqsh default creds
    _write(outfile, "\n[DEFAULT CREDENTIAL TEST]\n")
    valid_creds = []
    for user, pwd in MSSQL_DEFAULT_CREDS:
        stdout_c, _, rc = _run_tool(
            ['sqsh', '-S', f'{target}:{port}', '-U', user, '-P', pwd,
             '-C', 'SELECT @@VERSION;'], timeout=10)
        if rc == 0 and stdout_c and 'Microsoft' in stdout_c:
            valid_creds.append((user, pwd))
            _write(outfile, f"  [+] VALID: {user}:{pwd or '(empty)'}")
        else:
            _write(outfile, f"  [-] {user}:{pwd or '(empty)'}")

    out['valid_creds'] = valid_creds

    # CrackMapExec
    stdout, _, _ = _run_tool(
        ['crackmapexec', 'mssql', target, '-p', str(port)], timeout=30)
    if stdout:
        _write(outfile, f"\n[CrackMapExec]\n{stdout}")
        out['cme'] = stdout

    return out


# ─────────────────────────────────────────────────────────────
# Oracle TNS — Port 1521
# ─────────────────────────────────────────────────────────────

def _oracle_banner(target, port, timeout=5):
    """Send a TNS ping packet and parse the response for version strings."""
    tns_ping = (
        b'\x00\x57\x00\x00\x01\x00\x00\x00\x01\x36\x01\x2c'
        b'\x00\x00\x08\x00\x7f\xff\x7f\x08\x00\x00\x00\x01'
        b'\x00\x1a\x00\x3a\x00\x00\x02\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    )
    try:
        s = socket.create_connection((target, port), timeout=timeout)
        s.send(tns_ping)
        data = s.recv(2048)
        s.close()
        strings = re.findall(b'[\x20-\x7e]{4,}', data)
        return b' '.join(strings).decode(errors='replace')
    except Exception:
        return None


def enum_oracle(target, port, results_base):
    """
    Oracle TNS enumeration:
    - TNS banner and version
    - SID enumeration (nmap brute)
    - tnscmd10g version/status
    - nmap oracle scripts
    """
    out = {}
    rdir = make_results_dir(results_base, 'oracle')
    outfile = os.path.join(rdir, 'oracle_enum.txt')
    _write(outfile, _header('Oracle TNS', target, port))

    banner = _oracle_banner(target, port)
    if banner:
        out['banner'] = banner
        _write(outfile, f"[TNS BANNER]\n{banner}\n")

    # nmap oracle scripts
    stdout, _, _ = _nmap(target, port,
        'oracle-tns-version,oracle-sid-brute,oracle-enum-users',
        timeout=120)
    if stdout:
        _write(outfile, f"\n[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout

    # tnscmd10g
    for tool in ['tnscmd10g', 'tnscmd']:
        for action in ['version', 'status']:
            stdout, _, rc = _run_tool(
                [tool, action, '-h', target, '-p', str(port)], timeout=15)
            if stdout:
                _write(outfile, f"\n[{tool} {action}]\n{stdout}")
                out[f'tnscmd_{action}'] = stdout

    return out


# ─────────────────────────────────────────────────────────────
# IMAP — Ports 143, 993
# ─────────────────────────────────────────────────────────────

def enum_imap(target, port, results_base):
    """
    IMAP enumeration:
    - Banner grabbing
    - CAPABILITY command
    - STARTTLS detection
    - Login disabled check
    - nmap imap scripts
    """
    out = {}
    use_ssl = (port == 993)
    rdir = make_results_dir(results_base, 'imap')
    outfile = os.path.join(rdir, 'imap_enum.txt')
    _write(outfile, _header('IMAP', target, port))

    try:
        if use_ssl:
            conn = imaplib.IMAP4_SSL(target, port)
        else:
            conn = imaplib.IMAP4(target, port)

        banner = conn.welcome.decode(errors='replace') if conn.welcome else ''
        out['banner'] = banner
        _write(outfile, f"[BANNER]\n{banner}\n")

        typ, data = conn.capability()
        caps = ' '.join(
            c.decode(errors='replace') if isinstance(c, bytes) else str(c)
            for c in (data or [])
        )
        out['capabilities'] = caps
        _write(outfile, f"\n[CAPABILITIES]\n{caps}\n")

        if 'STARTTLS' in caps.upper():
            out['starttls'] = True
            _write(outfile, "\n[+] STARTTLS supported\n")
        if 'LOGINDISABLED' in caps.upper():
            out['login_disabled'] = True
            _write(outfile, "\n[+] LOGINDISABLED (plaintext login blocked without TLS)\n")

        conn.logout()
    except Exception as e:
        _write(outfile, f"[ERROR] {e}\n")

    stdout, _, _ = _nmap(target, port,
        'imap-capabilities,imap-ntlm-info')
    if stdout:
        _write(outfile, f"\n[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout

    return out


# ─────────────────────────────────────────────────────────────
# POP3 — Ports 110, 995
# ─────────────────────────────────────────────────────────────

def enum_pop3(target, port, results_base):
    """
    POP3 enumeration:
    - Banner grabbing
    - CAPA command (capabilities)
    - APOP timestamp extraction
    - STLS/STARTTLS detection
    - nmap pop3 scripts
    """
    out = {}
    use_ssl = (port == 995)
    rdir = make_results_dir(results_base, 'pop3')
    outfile = os.path.join(rdir, 'pop3_enum.txt')
    _write(outfile, _header('POP3', target, port))

    try:
        if use_ssl:
            conn = poplib.POP3_SSL(target, port)
        else:
            conn = poplib.POP3(target, port)

        banner = conn.getwelcome().decode(errors='replace')
        out['banner'] = banner
        _write(outfile, f"[BANNER]\n{banner}\n")

        # APOP timestamp
        apop_match = re.search(r'<[^>]+>', banner)
        if apop_match:
            _write(outfile, f"[+] APOP timestamp: {apop_match.group(0)}\n")
            out['apop_timestamp'] = apop_match.group(0)

        # CAPA
        try:
            resp = conn.capa()
            caps = {}
            if isinstance(resp, tuple):
                # First element is status, rest is list
                for item in resp:
                    if isinstance(item, list):
                        for cap in item:
                            if isinstance(cap, bytes):
                                caps[cap.decode(errors='replace')] = True
            cap_str = '\n'.join(caps.keys())
            _write(outfile, f"\n[CAPA]\n{cap_str}\n")
            out['capa'] = list(caps.keys())
        except Exception:
            pass

        conn.quit()
    except Exception as e:
        _write(outfile, f"[ERROR] {e}\n")

    stdout, _, _ = _nmap(target, port,
        'pop3-capabilities,pop3-ntlm-info')
    if stdout:
        _write(outfile, f"\n[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout

    return out


# ─────────────────────────────────────────────────────────────
# IPMI — Port 623 (UDP)
# ─────────────────────────────────────────────────────────────

def _ipmi_probe(target, port=623, timeout=3):
    """Send RMCP Ping to check if IPMI is alive."""
    rmcp_ping = bytes([
        0x06, 0x00, 0xff, 0x06,  # RMCP header (ASF ping)
        0x00, 0x00, 0x11, 0xbe,  # ASF IANA
        0x80,                     # Message type: Presence Ping
        0x00, 0x00, 0x00,
    ])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(rmcp_ping, (target, port))
        data, _ = s.recvfrom(256)
        s.close()
        return data
    except Exception:
        return None


def enum_ipmi(target, port, results_base):
    """
    IPMI 2.0 enumeration:
    - RMCP ping (liveness check)
    - Authentication capabilities (cipher 0 check)
    - nmap IPMI scripts (version, cipher-zero, hash dump)
    - ipmitool default credential check (ADMIN/ADMIN)
    """
    out = {}
    rdir = make_results_dir(results_base, 'ipmi')
    outfile = os.path.join(rdir, 'ipmi_enum.txt')
    _write(outfile, _header('IPMI', target, port))

    data = _ipmi_probe(target, port)
    if data:
        out['responsive'] = True
        _write(outfile, f"[RMCP PING RESPONSE] {data.hex()}\n")
    else:
        out['responsive'] = False
        _write(outfile, "[IPMI] No UDP response (may be filtered)\n")

    # nmap IPMI scripts (UDP)
    stdout, _, _ = _nmap(target, port,
        'ipmi-version,ipmi-cipher-zero,ipmi-brute',
        extra_args=['-sU'], timeout=60)
    if stdout:
        _write(outfile, f"\n[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout
        if 'CIPHER ZERO' in stdout.upper() or 'VULNERABLE' in stdout.upper():
            out['cipher0_bypass'] = True
            _write(outfile, "\n[!!!] CIPHER 0 authentication bypass detected!\n")

    # ipmitool default creds
    for user, pwd in [('ADMIN', 'ADMIN'), ('admin', 'admin'), ('root', 'calvin')]:
        stdout_i, _, rc = _run_tool(
            ['ipmitool', '-I', 'lanplus', '-H', target, '-U', user,
             '-P', pwd, 'chassis', 'status'], timeout=15)
        if rc == 0 and stdout_i:
            _write(outfile, f"\n[!!!] DEFAULT CREDS VALID: {user}:{pwd}\n{stdout_i}")
            out['default_creds'] = (user, pwd)
            break

    return out


# ─────────────────────────────────────────────────────────────
# HTTP/HTTPS — Ports 80, 443, 8080, 8443
# ─────────────────────────────────────────────────────────────

def enum_http(target, port, results_base, scheme='http'):
    """
    HTTP/HTTPS deep enumeration:
    - whatweb technology fingerprinting
    - wafw00f WAF detection
    - nikto vulnerability scanner
    - Directory brute-force: ffuf → dirb → gobuster (in priority order)
    - nmap http scripts (title, headers, methods, shellshock, robots, php-version)
    """
    out = {}
    label = scheme  # 'http' or 'https'
    base_url = (f"{scheme}://{target}"
                if port in (80, 443)
                else f"{scheme}://{target}:{port}")
    rdir = make_results_dir(results_base, label)
    outfile = os.path.join(rdir, 'http_enum.txt')
    _write(outfile, _header(f'HTTP ({scheme.upper()})', target, port))
    _write(outfile, f"[TARGET URL] {base_url}\n")

    # 1. whatweb
    stdout, _, _ = _run_tool(
        ['whatweb', '--color=never', '-a', '3', base_url], timeout=30)
    if stdout:
        _write(outfile, f"\n[whatweb — Technology Fingerprinting]\n{stdout}")
        out['whatweb'] = stdout

    # 2. wafw00f
    stdout, _, _ = _run_tool(['wafw00f', base_url], timeout=30)
    if stdout:
        _write(outfile, f"\n[wafw00f — WAF Detection]\n{stdout}")
        out['waf'] = stdout

    # 3. nikto
    nikto_out = os.path.join(rdir, 'nikto.txt')
    stdout, _, _ = _run_tool(
        ['nikto', '-h', base_url, '-o', nikto_out, '-Format', 'txt',
         '-nointeractive', '-Tuning', '123457890'],
        timeout=360)
    if stdout:
        _write(outfile, f"\n[nikto — Vulnerability Scanner]\n{stdout[:8000]}")
        out['nikto'] = stdout[:8000]

    # 4. Directory brute-force — ffuf first, then dirb, then gobuster
    wordlist_candidates = [
        '/usr/share/seclists/Discovery/Web-Content/common.txt',
        '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
        '/usr/share/wordlists/dirb/common.txt',
        '/usr/share/wordlists/dirb/big.txt',
    ]
    wordlist = next((w for w in wordlist_candidates if os.path.exists(w)), None)

    if wordlist:
        ffuf_json = os.path.join(rdir, 'ffuf_dirs.json')
        stdout_f, _, rc_f = _run_tool(
            ['ffuf', '-u', f'{base_url}/FUZZ', '-w', wordlist,
             '-o', ffuf_json, '-of', 'json',
             '-mc', '200,201,204,301,302,307,401,403,405',
             '-t', '50', '-timeout', '10', '-s'],
            timeout=360)
        if rc_f == 0:
            _write(outfile, f"\n[ffuf — Directory Brute-force]\nResults saved to {ffuf_json}\n")
            if stdout_f:
                _write(outfile, stdout_f[:3000])
            out['ffuf_output'] = ffuf_json
        else:
            # Fallback: dirb
            dirb_out_file = os.path.join(rdir, 'dirb.txt')
            stdout_d, _, rc_d = _run_tool(
                ['dirb', base_url, wordlist, '-o', dirb_out_file,
                 '-S', '-r', '-z', '100'], timeout=360)
            if stdout_d:
                _write(outfile, f"\n[dirb — Directory Brute-force]\n{stdout_d[:4000]}")
                out['dirb'] = stdout_d[:4000]
            else:
                # Final fallback: gobuster
                stdout_g, _, _ = _run_tool(
                    ['gobuster', 'dir', '-u', base_url, '-w', wordlist,
                     '-t', '30', '--no-error', '-q', '-o',
                     os.path.join(rdir, 'gobuster.txt')],
                    timeout=360)
                if stdout_g:
                    _write(outfile, f"\n[gobuster]\n{stdout_g[:4000]}")
                    out['gobuster'] = stdout_g[:4000]
    else:
        _write(outfile, "\n[Dir Brute-force] No wordlist found on system\n")

    # 5. nmap http scripts
    stdout, _, _ = _nmap(target, port,
        ('http-title,http-headers,http-methods,http-auth-finder,'
         'http-robots.txt,http-server-header,http-shellshock,'
         'http-php-version,http-generator'),
        timeout=60)
    if stdout:
        _write(outfile, f"\n[NMAP SCRIPTS]\n{stdout}")
        out['nmap'] = stdout

    return out


# ─────────────────────────────────────────────────────────────
# Service Handler Registry
# ─────────────────────────────────────────────────────────────

SERVICE_HANDLERS = {
    21:    ('ftp',    enum_ftp),
    22:    ('ssh',    enum_ssh),
    25:    ('smtp',   enum_smtp),
    53:    ('dns',    enum_dns),
    80:    ('http',   lambda t, p, r: enum_http(t, p, r, 'http')),
    110:   ('pop3',   enum_pop3),
    139:   ('smb',    enum_smb),
    143:   ('imap',   enum_imap),
    161:   ('snmp',   enum_snmp),
    443:   ('https',  lambda t, p, r: enum_http(t, p, r, 'https')),
    445:   ('smb',    enum_smb),
    465:   ('smtp',   enum_smtp),
    587:   ('smtp',   enum_smtp),
    623:   ('ipmi',   enum_ipmi),
    993:   ('imap',   enum_imap),
    995:   ('pop3',   enum_pop3),
    1433:  ('mssql',  enum_mssql),
    1521:  ('oracle', enum_oracle),
    2049:  ('nfs',    enum_nfs),
    3306:  ('mysql',  enum_mysql),
    8080:  ('http',   lambda t, p, r: enum_http(t, p, r, 'http')),
    8443:  ('https',  lambda t, p, r: enum_http(t, p, r, 'https')),
}

SERVICE_DESCRIPTIONS = {
    'ftp':    'File Transfer Protocol',
    'ssh':    'Secure Shell',
    'smtp':   'Simple Mail Transfer Protocol',
    'dns':    'Domain Name System',
    'http':   'Hypertext Transfer Protocol',
    'https':  'HTTP Secure (TLS)',
    'pop3':   'Post Office Protocol v3',
    'imap':   'Internet Message Access Protocol',
    'snmp':   'Simple Network Management Protocol',
    'smb':    'Server Message Block',
    'nfs':    'Network File System',
    'mysql':  'MySQL Database',
    'mssql':  'Microsoft SQL Server',
    'oracle': 'Oracle TNS Listener',
    'ipmi':   'Intelligent Platform Mgmt Interface',
}


# ─────────────────────────────────────────────────────────────
# Main Dispatcher
# ─────────────────────────────────────────────────────────────

def run_service_enum(target, open_ports, results_base, max_workers=4, callback=None):
    """
    Dispatch per-service enumeration for all open ports.

    Creates results/<service>/ directories automatically.

    Args:
        target:       Hostname or IP address
        open_ports:   List of (port, service_label, banner) tuples from port scanner
        results_base: Base directory where results/<service>/ dirs will be created
        max_workers:  Number of parallel enumeration threads
        callback:     Optional fn(port, svc_name, status, result) called per service

    Returns:
        dict mapping port -> {'service': name, 'status': 'ok'|'error', 'results': data}
    """
    all_results = {}
    seen = set()   # deduplicate same logical service (139 + 445 → smb once each port)
    tasks = []

    for port, _, _ in open_ports:
        handler = SERVICE_HANDLERS.get(port)
        if not handler:
            continue
        svc_name, fn = handler
        # Allow same service on different ports (e.g., http on 80 and 8080)
        key = f"{svc_name}:{port}"
        if key in seen:
            continue
        seen.add(key)
        tasks.append((port, svc_name, fn))

    def _run(port, svc_name, fn):
        try:
            result = fn(target, port, results_base)
            return port, svc_name, 'ok', result
        except Exception as e:
            return port, svc_name, 'error', str(e)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_run, p, s, f): (p, s) for p, s, f in tasks}
        for future in as_completed(futures):
            port, svc_name, status, result = future.result()
            all_results[port] = {
                'service': svc_name,
                'status': status,
                'results': result,
            }
            if callback:
                callback(port, svc_name, status, result)

    return all_results