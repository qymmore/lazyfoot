import subprocess
import os
import re
from datetime import datetime
import argparse

RESULTS_DIR = "results"

def run_nmap_scan(target):
    print(f"[+] Running nmap scan on {target}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"nmap_{target.replace('.', '_')}_{timestamp}.txt"
    command = ["nmap", "-sS", "-sV", "-T4", target]
    with open(output_file, "w") as f:
        subprocess.run(command, stdout=f)
    return output_file

def parse_services(nmap_output_file):
    services = set()
    with open(nmap_output_file, "r") as file:
        for line in file:
            match = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
            if match:
                port, service = match.groups()
                services.add(service)
    return services

def create_service_dirs(services):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    for service in services:
        service_path = os.path.join(RESULTS_DIR, service)
        os.makedirs(service_path, exist_ok=True)
        print(f"[+] Created directory for {service} at {service_path}")

def store_scan_results(service_dirs, nmap_output_file):
    with open(nmap_output_file, "r") as f:
        content = f.read()
        for service in service_dirs:
            service_path = os.path.join(RESULTS_DIR, service, "nmap_output.txt")
            with open(service_path, "w") as out:
                out.write(content)

def main():
    parser = argparse.ArgumentParser(description="Footprinting & web enumeration tool")
    parser.add_argument("target", help="Enter target IP/FQDN")
    args = parser.parse_args()

    nmap_output = run_nmap_scan(args.target)
    found_services = parse_services(nmap_output)
    create_service_dirs(found_services)
    store_scan_results(found_services, nmap_output)
    print("[+] Initial nmap scan complete.")

if __name__ == "__main__":
    main()
