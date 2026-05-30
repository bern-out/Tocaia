#!/usr/bin/env python3
import argparse
from pathlib import Path
import json
import re
import os
from datetime import datetime
import subprocess
from custom_logging import *
import threading
from typing import TypedDict
import shutil

CONST_DOMAINS_FOLDER = 'domains'
CONST_DOMAIN_FOLDER = None
CONST_DOMAIN_REPORT = None
CONST_RECON_TIMESTAMP = ''
CONST_INTERESTING_PORTS = [
    # databases
    '3306', '5432', '27017', '6379', '9200', '9300', '5984', '1433',
    # Dev / Debug / Admin
    '8080', '8443', '8888', '9090', '3000', '4848', '9000',
    # Remote Access
    '2222', '5900', '3389', '5985', '7070',
    # Message Queues
    '5672', '9092', '2181', '4369', '11211',
    # Cloud / Containers
    '2375', '2379', '10250'
]

RECON_TOOLS = [
    {
        "name": "subfinder",
        "cmd": lambda domain: ['subfinder', '-d', domain, '-silent', '-nc', '-all'],
    },
    {
        "name": "assetfinder",
        "cmd": lambda domain: ['assetfinder', '--subs-only', domain],
    },
    {
        "name": "amass",
        "cmd": lambda domain: ['amass', 'enum', '-silent', '-d', domain],
    },
]

class HostReport(TypedDict):
    nmap_scan: list[str]
    nuclei_scan: list[str]

def banner_box(text: str, subtitle: str):
    lines = text.split("\n")
    if subtitle:
        lines.append(subtitle)

    width = max(len(line) for line in lines)

    print(bcolors.OKCYAN)
    print("┌" + "─" * (width + 2) + "┐")

    for line in lines:
        print("│ " + line.ljust(width) + " │")

    print("└" + "─" * (width + 2) + "┘")
    
    print("\033[0m")

def print_usage():
    print('''
Usage:
    recon <domain>
    ''')


def is_domain_valid(domain: str) -> bool:
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None


def stream_output(pipe, target_stdin, lock: threading.Lock):
    try:
        for line in iter(pipe.readline, b''):
            with lock:
                target_stdin.write(line)
                target_stdin.flush()
    finally:
        pipe.close()


def run_subdomain_discovery(domain: str) -> tuple[str, str]:
    lock = threading.Lock()

    commands = build_commands(domain=domain)

    if len(commands) < 1:
        tools: list[str] = [str(tool['name']) for tool in RECON_TOOLS]
        raise Exception(f"No enumeration tools are installed: {', '.join(tools)}")

    p_tr = subprocess.Popen(
        ['tr', '[:upper:]', '[:lower:]'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE
    )

    p_sort = subprocess.Popen(
        ['sort', '-u'],
        stdin=p_tr.stdout,
        stdout=subprocess.PIPE,
        text=True
    )

    threads: list[threading.Thread] = []

    for cmd in commands:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        t = threading.Thread(
            target=stream_output,
            args=(p.stdout, p_tr.stdin, lock)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if p_tr.stdin:
        p_tr.stdin.close()
    standard_out, standard_err = p_sort.communicate()

    return standard_out, standard_err


def run_directory_setup(name: str):
    global CONST_DOMAINS_FOLDER, CONST_DOMAIN_FOLDER, CONST_DOMAIN_REPORT, CONST_RECON_TIMESTAMP
    CONST_DOMAIN_FOLDER = f"{CONST_DOMAINS_FOLDER}/{name}"

    fileDateFormat = "%Y%m%d_%H%M%S"
    timestamp = datetime.now().strftime(fileDateFormat)
    CONST_RECON_TIMESTAMP = timestamp

    CONST_DOMAIN_FILENAME = str(timestamp) + '.json'

    CONST_DOMAIN_REPORT =  CONST_DOMAIN_FOLDER + '/' + CONST_DOMAIN_FILENAME

    os.makedirs(CONST_DOMAIN_FOLDER, exist_ok=True)

def check_alive_hosts(stdout: str):
    command = ['httpx', '-silent']

    result = subprocess.run(
        command,
        input=stdout,
        text=True,
        capture_output=True
    )

    alive_hosts = result.stdout.splitlines()

    return alive_hosts


def scan_host_ports(host: str) -> list[str]:
    result = [
        'nmap', '-Pn', '-T4', '--top-ports', '1000', '--open', host
    ]

    result = subprocess.run(
        result,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    ports: list[str] = []

    for line in result.stdout.splitlines():
        if '/tcp' or '/udp' in line:
            first = line.split('/')[0].strip()
            if first.isdigit():
                ports.append(first)

    return ports

def scan_all_host_ports(host: str) -> list[str]:
    nmap_cmd = [
        'nmap', '-Pn', '-T5', '-p-', '--open', host
    ]

    result = subprocess.run(
        nmap_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    ports: list[str] = []

    for line in result.stdout.splitlines():
        if '/tcp' or '/udp' in line:
            first = line.split('/')[0].strip()
            if first.isdigit():
                ports.append(first)

    return ports


def verify_for_honeypot(host: str) -> bool:
    ephemeral_ports = ['65535', '49152']
    separator = ','
    str_ephemeral_ports = separator.join(ephemeral_ports)

    nmap_cmd = [
        'nmap', '-Pn', '-p', str_ephemeral_ports, '--open', host
    ]

    result = subprocess.run(
        nmap_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    ports: list[str] = []

    for line in result.stdout.splitlines():
        if '/tcp' or '/udp' in line:
            first = line.split('/')[0].strip()
            if first.isdigit():
                ports.append(first)

    return len(ports) > 0


def run_http_nuclei_scan(host: str) -> list[str]:
    nuclei_cmd = [
        'nuclei', '-t', 'http', '-nc', '-silent', '-u', host
    ]

    result = subprocess.run(
        nuclei_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    return result.stdout.splitlines()

def run_notify(message: str):
    notify_cmd = [
        'notify', '-bulk', '-id', 'recon-lab'
    ]

    subprocess.run(
        notify_cmd,
        input=message,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )


def is_tool_installed(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def build_commands(domain: str) -> list[list[str]]:
    commands = []
    for tool in RECON_TOOLS:
        if is_tool_installed(tool_name=tool['name']):
            commands.append(tool['cmd'](domain))
            continue
        print_warn(f"Tool not installed: {tool['name']}")
        print_info("Skipping.")
    return commands


def main():
    parser = argparse.ArgumentParser(description="Subdomain Automation for Discovery & Scanning hosts")
    parser.add_argument('-d', '--domain', required=True, help='Target domain that will be scanned')
    parser.add_argument('-igh', '--ignore-honeypot', action='store_true', help="Skips ephemeral ports scan.")

    args = parser.parse_args()
    if not is_domain_valid(args.domain):
        raise argparse.ArgumentError(args.domain, "Domain format not valid.")

    banner_box('BUG BOUNTY', 'Automating Subdomain Discovery & Scanning')

    print_info('Setting up directories')
    run_directory_setup(name=args.domain)

    print_ok(f'Target: {args.domain}')

    tools: list[str] = [str(tool['name']) for tool in RECON_TOOLS]

    print_info(f'Enumerating subdomains using {", ".join(tools)}')
    subdomains_stdout, _ = run_subdomain_discovery(domain=args.domain)

    print_ok(f"Got a list of {len(subdomains_stdout.splitlines())} subdomains!")

    print_info("Using httpx to check for alive hosts.")
    http_hosts = check_alive_hosts(subdomains_stdout)
    subdomains: list[str] = []

    for http_host in http_hosts:
        _, subdomain = http_host.split("//")
        subdomains.append(subdomain)

    global CONST_DOMAIN_REPORT
    if CONST_DOMAIN_REPORT is None:
        raise FileNotFoundError(f"Domain file not found: {CONST_DOMAIN_REPORT}")

    report_file_path = Path(CONST_DOMAIN_REPORT)

    reports: dict[str, HostReport] = {}

    if len(subdomains) > 0:
        print_info("Starting nmap scan for hosts.")
        for host in subdomains:

            host_report: HostReport = {
                'nmap_scan': [],
                'nuclei_scan': [],
            }

            print_info(f"Scanning ports: {host}")

            ports = scan_host_ports(host=host)

            if len(ports) < 1:
                print_warn(f"No ports found for {host}")
                break

            common = set(CONST_INTERESTING_PORTS) & set(ports)
            if bool(common):
                print_warn(f"Interesting ports found: {common}")

                print_info("Sending notification to user.")
                run_notify(f"Interesting ports fund for {host}")

                if not args.ignore_honeypot:
                    print_info("Verifing if it's a honeypot.")

                    if verify_for_honeypot(host=host):
                        print_warn("High ephemeral ports detected (port spoofer). Skipping target.")
                        continue

                    print_info("The host doesn't seem to be a honeypot.")

                print_info("Going for full port scan.")

                ports = scan_all_host_ports(host=host)

                print_info(f"All ports open for {host}: {ports}")

            print_ok(f"{len(ports)} ports found for {host}")

            host_report['nmap_scan'] = ports

            print_info(f"Running nuclei against {host}")
            found_vulnerabilities = run_http_nuclei_scan(host=host)

            if len(found_vulnerabilities) > 0:
                print_info(f"Found {len(found_vulnerabilities)} possible vulnerabilities.")

            host_report['nuclei_scan'] = found_vulnerabilities
            reports.setdefault(host, host_report)

    else:
        print_warn("No alive hosts found. Skipping port scan.")

    with open(report_file_path, 'w') as f:
        json.dump(reports, f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warn('CTRL + C signal received. Exiting program...')
    except Exception as e:
        print_error(f'An error occurred: {type(e).__name__} - {e}')
