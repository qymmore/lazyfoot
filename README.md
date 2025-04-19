(This is a draft)

I am making this tool because I am lazy and I like to automate tedious processes such as footprinting and service enumeration (hence the name LazyFoot)

This tool will footprint all of the following open services on the target host:
- FTP
- SMB
- SNMP
- mySQL databases
- Oracle TNS
- SMTP
- NFS 
- DNS 
- IMAP/POP3
- MSSQL
- IPMI

I also want to include web enumeration (possibly)

## Goals

#### 1. **Initial nmap scan**

- Run an nmap scan (`nmap -sS -Pn -T4`) to discover open ports.
- Parse results to identify services (FTP, SMTP, SNMP, HTTP, etc.)

#### 2. **Further Enumeration**

- For each open port, create a subdirectory (`results/ftp/`, `results/smtp/`, etc.).
- Run tools based on port/service:
    - **FTP (21):** anonymous login check, banner grabbing
    - **SMTP (25):** `smtp-user-enum`, `nmap --script smtp-commands`
    - **SNMP (161):** `snmpwalk`, `onesixtyone`
    - **HTTP(S):** whatweb, nikto, dirb/ffuf

#### 3. **DNS & Web Scanning**

- **Zone Transfers:** `dig axfr` on discovered NS records
- **Subdomain Brute forcing:** `ffuf`, `dnsenum`, or `dnsrecon`
- **Web Crawling:** `gobuster`, `feroxbuster`, or write custom crawler with `requests` + `BeautifulSoup`
- **Fingerprinting:** `whatweb`, `wappalyzer-cli`, custom headers scan