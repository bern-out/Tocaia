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

    commands = [
        ['subfinder', '-d', domain, '-silent', '-nc', '-all'],
        ['assetfinder', '--subs-only', domain],
        ['amass', 'enum', '-silent', '-d', domain]
    ]

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


def main():
    parser = argparse.ArgumentParser(description="Subdomain Automation for Discovery & Scanning hosts")
    parser.add_argument('-d', '--domain', required=True, help='Target domain that will be scanned')

    args = parser.parse_args()
    if not is_domain_valid(args.domain):
        raise argparse.ArgumentError(args.domain, "Domain format not valid.")

    banner_box('BUG BOUNTY', 'Automating Subdomain Discovery & Scanning')

    print_info('Setting up directories')
    run_directory_setup(name=args.domain)

    print_ok(f'Target: {args.domain}')
    print_info('Enumerating subdomains using subfinder, assetfinder, and amass.')
    subdomains_stdout, _ = run_subdomain_discovery(domain=args.domain)

    print_ok(f"Got a list of {len(subdomains_stdout.splitlines())} subdomains!")

    print_info("Using httpx to check for alive hosts.")
    http_hosts = check_alive_hosts(subdomains_stdout)
    subdomains: list[str] = []

    for http_host in http_hosts:
        _, subdomain = http_host.split("//")
        subdomains.append(subdomain)


    report = {
        'alive-subdomains': [],
        'port-scan': {},
    }

    global CONST_DOMAIN_REPORT
    if CONST_DOMAIN_REPORT is None:
        raise FileNotFoundError(f"Domain file not found: {CONST_DOMAIN_REPORT}")

    report_file_path = Path(CONST_DOMAIN_REPORT)

    report['alive-subdomains'] = subdomains
    report['port-scan'] = {}

    if len(subdomains) > 0:
        print_info("Starting nmap scan for hosts.")
        for host in subdomains:
            print_info(f"Scanning ports: {host}")

            ports = scan_host_ports(host=host)

            if len(ports) < 1:
                print_warn(f"No ports found for {host}")
                break

            common = set(CONST_INTERESTING_PORTS) & set(ports)
            if bool(common):
                print_warn(f"Interesting ports found: {common}")

                print_info("Verifing if it's a honeypot.")
                if verify_for_honeypot(host=host):
                    print_warn("High ephemeral ports detected. Skipping target.")
                    continue

                print_info("The host doesn't seem to be a honeypot. Going for full ports scan")
                ports = scan_all_host_ports(host=host)

                print_info(f"All ports open for {host}: {ports}")

            print_ok(f"{len(ports)} ports found for {host}")

            report['port-scan'][host] = ports

    else:
        print_warn("No alive hosts found. Skipping port scan.")

    with open(report_file_path, 'w') as f:
        json.dump(report, f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warn('CTRL + C signal received. Exiting program...')
    except Exception as e:
        print_error(f'An error occurred: {type(e).__name__} - {e}')
