#!/usr/bin/env python3
import argparse
from pathlib import Path
import sys
import re
import os
from datetime import datetime
import subprocess
from custom_logging import *
import threading

DOMAINS_FOLDER_RELATIVE_PATH = 'domains'
DOMAIN_FOLDER = None
DOMAIN_FILENAME = None
DOMAIN_FILE_RELATIVE_PATH = None


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
        ['amass', 'enum', '-passive', '-d', domain]
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
    # example: ./domains/<domain>/
    global DOMAINS_FOLDER_RELATIVE_PATH
    DOMAINS_FOLDER_RELATIVE_PATH = f"{DOMAINS_FOLDER_RELATIVE_PATH}/{name}"

    global DOMAIN_FILENAME
    fileDateFormat = "%Y%m%d_%H%M%S"
    # example: 20260511_160028.txt
    DOMAIN_FILENAME = str(datetime.now().strftime(fileDateFormat)) + '.txt'

    # example: ./domains/<domain>/20260511_160028.txt
    global DOMAIN_FILE_RELATIVE_PATH
    DOMAIN_FILE_RELATIVE_PATH =  DOMAINS_FOLDER_RELATIVE_PATH + '/' + DOMAIN_FILENAME

    os.makedirs(DOMAINS_FOLDER_RELATIVE_PATH, exist_ok=True)


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


def main():
    parser = argparse.ArgumentParser(description="Subdomain Automation for Discovery & Scanning hosts")
    parser.add_argument('-d', '--domain', required=True)

    args = parser.parse_args()
    if not is_domain_valid(args.domain):
        raise argparse.ArgumentError(args.domain, "Domain format not valid.")

    banner_box('BUG BOUNTY', 'Automating Subdomain Discovery & Scanning')

    print_info(f'Setting up directories')
    run_directory_setup(name=args.domain)

    print_ok(f'target: {args.domain}')
    print_info(f'Enumerating subdomains using subfinder, assetfinder, and amass.\nThis could take a while.')
    stdout, _ = run_subdomain_discovery(domain=args.domain)

    print_info(f"Using httpx to check for alive hosts.")
    hosts = check_alive_hosts(stdout)

    global DOMAIN_FILE_RELATIVE_PATH
    if DOMAIN_FILE_RELATIVE_PATH is None:
        raise FileNotFoundError(f"Domain file not found: {DOMAIN_FILE_RELATIVE_PATH}")

    domain_file_relative_path = Path(DOMAIN_FILE_RELATIVE_PATH)
    with open(domain_file_relative_path, 'w') as f:
        f.write('\n'.join(hosts))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warn('CTRL + C signal received. Exiting program...')
    except Exception as e:
        print_error(f'An error occurred: {type(e).__name__} - {e}')
