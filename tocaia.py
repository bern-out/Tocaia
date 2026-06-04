#!/usr/bin/env python3
from urllib3.util import parse_url
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import tempfile
import argparse
from pathlib import Path
import json
import re
import os
from datetime import datetime
import subprocess
from typing import Dict
from custom_logging import *
import threading
import shutil

CONST_DOMAINS_FOLDER = 'domains'
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

DNS_ENUM_RECON_TOOLS = [
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

@dataclass
class HostReport:
    nmap_scan: list[str]
    nuclei_scan: list[str]


@dataclass
class DomainWorkspace:
    domain_path: Path = field(default_factory=Path)
    timestamp: str = ''
    report_path: Path = field(default_factory=Path)


build_port_alert = lambda host, ports, message: f"""
🚨 **{message}**

🎯 **Host:** `{host}`

📡 **Open Ports**
```text
{ports}
```
"""


def banner_box(text: str, subtitle: str):
    lines = text.split("\n")
    if subtitle:
        lines.append(subtitle)

    width = max(len(line) for line in lines)

    print('\033[96m')
    print("┌" + "─" * (width + 2) + "┐")

    for line in lines:
        print("│ " + line.ljust(width) + " │")

    print("└" + "─" * (width + 2) + "┘")
    
    print("\033[0m")


def is_domain_valid(domain: str) -> str:
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(pattern, domain):
        raise argparse.ArgumentTypeError(f"Invalid domain format. Example: domain.com")

    return domain


def stream_output(pipe, target_stdin, lock: threading.Lock, logger: CustomLogger):
    try:
        for line in iter(pipe.readline, b''):
            with lock:
                try:
                    target_stdin.write(line)
                    target_stdin.flush()
                except BrokenPipeError as e:
                    logger.error(f"Stream output error: {e}")
                    break
    finally:
        pipe.close()


def run_subdomain_discovery(domain: str, log: CustomLogger) -> tuple[str, str]:
    lock = threading.Lock()

    commands = build_commands(domain=domain, logger=log)

    if len(commands) < 1:
        tools: list[str] = [str(tool['name']) for tool in DNS_ENUM_RECON_TOOLS]
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

    if p_tr.stdout:
        p_tr.stdout.close()

    threads: list[threading.Thread] = []

    for cmd in commands:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        t = threading.Thread(
            target=stream_output,
            args=(p.stdout, p_tr.stdin, lock, log)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if p_tr.stdin:
        p_tr.stdin.close()
    standard_out, standard_err = p_sort.communicate()

    return standard_out, standard_err


def run_directory_setup(
    main_folder: Path,
    date_format: str
) -> DomainWorkspace:
    workspace = DomainWorkspace()

    workspace.domain_path = main_folder
    workspace.timestamp = datetime.now().strftime(date_format)

    filename = str(workspace.timestamp) + '.json'

    workspace.report_path =  Path(workspace.domain_path, filename)

    workspace.domain_path.mkdir(parents=True, exist_ok=True)

    return workspace


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
    completed_process = [
        'nmap', '-Pn', '-T4', '--top-ports', '1000', '--open', host
    ]

    completed_process = subprocess.run(
        completed_process,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    ports: list[str] = parse_nmap_ports_stdout(process=completed_process)

    return ports

def scan_all_host_ports(host: str) -> list[str]:
    nmap_cmd = [
        'nmap', '-Pn', '-T5', '-p-', '--open', host
    ]

    completed_process = subprocess.run(
        nmap_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    ports: list[str] = parse_nmap_ports_stdout(process=completed_process)

    return ports


def verify_for_honeypot(host: str) -> bool:
    ephemeral_ports = ['65535', '49152']
    separator = ','
    str_ephemeral_ports = separator.join(ephemeral_ports)

    nmap_cmd = [
        'nmap', '-Pn', '-p', str_ephemeral_ports, '--open', host
    ]

    completed_process = subprocess.run(
        nmap_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    ports: list[str] = parse_nmap_ports_stdout(process=completed_process)

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


def build_commands(domain: str, logger: CustomLogger) -> list[list[str]]:
    commands = []
    for tool in DNS_ENUM_RECON_TOOLS:
        if is_tool_installed(tool_name=tool['name']):
            commands.append(tool['cmd'](domain))
            continue
        logger.warn(f"Tool not installed: {tool['name']}")
        logger.info("Skipping.")
    return commands


def take_screenshot(hosts_file: str, output_dir: str | None = None) -> None:
    cmd = [
        'eyewitness',
        '-f',
        hosts_file,
        '--no-prompt',
    ]

    if output_dir is not None:
        cmd += [
            '-d',
            output_dir
        ]

    subprocess.run(cmd)

def parse_nmap_ports_stdout(process: subprocess.CompletedProcess[str]) -> list[str]:
    ports: list[str] = []

    for line in process.stdout.splitlines():
        if '/tcp' in line or '/udp' in line:
            first = line.split('/')[0].strip()
            if first.isdigit():
                ports.append(first)

    return ports


def process_domain(domain: str, args: argparse.Namespace, logger: CustomLogger):
    domain_folder_path = Path(CONST_DOMAINS_FOLDER, domain)

    logger.info('Setting up directories')

    dateformat = "%Y%m%d_%H%M%S"
    workspace = run_directory_setup(domain_folder_path, dateformat)
    init_date = datetime.strptime(workspace.timestamp, dateformat)
    interesting_ports = CONST_INTERESTING_PORTS
    dns_enumeration_tools = DNS_ENUM_RECON_TOOLS

    logger.info(f'Target: {domain}')
    logger.info(f"Output: {workspace.domain_path}")
    logger.info(f"Initializing at {init_date}")

    tools: list[str] = [str(tool['name']) for tool in dns_enumeration_tools]

    logger.info(f'Enumerating subdomains using {", ".join(tools)}')
    subdomains_stdout, _ = run_subdomain_discovery(domain=domain, log=logger)

    if len(subdomains_stdout.splitlines()) < 1:
        logger.error("No subdomains found for host.")
        return

    logger.info(f"Got a list of {len(subdomains_stdout.splitlines())} subdomains!")

    logger.info("Using httpx to check for alive hosts.")
    http_hosts = check_alive_hosts(subdomains_stdout)

    if len(http_hosts) < 1:
        logger.warn("There is no alive hosts to continue scanning.")
        return

    logger.info(f"Got a list of {len(http_hosts)} subdomains that are active right now.")

    subdomains: list[str] = []

    screenshot_tool = 'eyewitness'
    if is_tool_installed(screenshot_tool):
        logger.info(f'Taking screenshots of alive hosts with {screenshot_tool}.')

        ew_dir = f"{domain_folder_path.as_posix()}/{screenshot_tool}"
        shutil.rmtree(ew_dir, ignore_errors=True)
        os.makedirs(ew_dir, exist_ok=True)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp:
            tmp.write('\n'.join(http_hosts) + '\n')
            tmp_path = tmp.name

        try:
            take_screenshot(tmp_path, ew_dir)
        finally:
            os.unlink(tmp_path)
    else:
        logger.warn(f"Tool not installed: {screenshot_tool}")
        logger.info('Skipping.')

    for http_host in http_hosts:
        url = parse_url(http_host)
        host = str(url.host)
        subdomains.append(host)

    reports: dict[str, Dict] = {}

    if len(subdomains) > 0:
        logger.info("Starting nmap scan for hosts.")
        for host in subdomains:
            host_report = HostReport(
                nmap_scan=[],
                nuclei_scan=[],
            )

            logger.info(f"Scanning ports: {host}")

            ports = scan_host_ports(host=host)

            if len(ports) < 1:
                logger.warn(f"No ports found for {host}")
                continue

            common = set(interesting_ports) & set(ports)
            if bool(common):
                logger.warn(f"Interesting ports found: {common}")

                if not args.ignore_honeypot:
                    logger.info("Verifing if it's a honeypot.")

                    if verify_for_honeypot(host=host):
                        logger.warn("High ephemeral ports detected (port spoofer). Skipping target.")
                        continue

                    logger.info("The host doesn't seem to be a honeypot.")

                logger.info("Going for full port scan.")

                ports = scan_all_host_ports(host=host)

                logger.info(f"All ports open for {host}: {ports}")

                logger.info("Sending notification to user.")
                run_notify(build_port_alert(host, ports, message="Interesting ports found."))

            logger.info(f"{len(ports)} ports found for {host}")

            host_report.nmap_scan = ports

            logger.info(f"Running nuclei against {host}")
            found_vulnerabilities = run_http_nuclei_scan(host=host)

            if len(found_vulnerabilities) > 0:
                logger.info(f"Found {len(found_vulnerabilities)} possible vulnerabilities.")

            host_report.nuclei_scan = found_vulnerabilities
            reports.setdefault(host, asdict(host_report))

    else:
        logger.warn("No alive hosts found. Skipping port scan.")

    with open(workspace.report_path, 'w') as f:
        json.dump(reports, f, indent=4, ensure_ascii=False)



def main():
    max_workers_default = 10

    parser = argparse.ArgumentParser(description="Subdomain Automation for Discovery & Scanning hosts")

    domainGroup = parser.add_mutually_exclusive_group(required=True)
    domainGroup.add_argument(
        '-d',
        '--domain', 
        type=is_domain_valid, 
        help=f'Target domain that will be scanned (default={max_workers_default}).'
    )
    domainGroup.add_argument('-f', '--file', type=Path, help='Target domains that will be scanned.')

    parser.add_argument('-mw', '--max-workers', type=int, default=10, help='The maximoum number of active workers.')
    parser.add_argument('-igh', '--ignore-honeypot', action='store_true', help="Skips ephemeral ports scan.")
    parser.add_argument('-o', '--output-log', type=Path, help='Redirect logs to a file.')

    args = parser.parse_args()
    domains: list[str] = []

    if args.file:
        with args.file.open('r') as f:
            domains += [d.strip() for d in f.read().splitlines() if d.strip()]
    else:
        domains.append(args.domain)

    if args.output_log:
        CustomLogger.set_log_file(args.output_log)

    banner_box('BUG BOUNTY', 'Automating Subdomain Discovery & Scanning')

    max_workers = min(args.max_workers, len(domains))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures_list = [
            executor.submit(
                process_domain, domain, args, CustomLogger(
                    domain=domain,
                )
            )
            for domain in domains
        ]

        for future in as_completed(futures_list):
            try:
                future.result()
            except Exception as e:
                print(f"Domain scan failed: {e}")

    print("Exiting...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('CTRL + C signal received. Exiting program...')
    except Exception as e:
        print(f'An error occurred: {type(e).__name__} - {e}')

