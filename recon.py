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

SUBDOMAINS_FOLDER = 'domains'
SUBDOMAINS_FILENAME = None
SUBDOMAINS_FILENAME_FULL_PATH = None


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
        stdout=subprocess.PIPE
    )

    p_anew = subprocess.Popen(
        ['anew', str(SUBDOMAINS_FILENAME_FULL_PATH)],
        stdin=p_sort.stdout,
        stdout=subprocess.PIPE,
        text=True,
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
    standard_out, standard_err = p_anew.communicate()

    return standard_out, standard_err


def run_directory_setup(name: str):
    subdomain_folder_path = Path(SUBDOMAINS_FOLDER)
    os.makedirs(subdomain_folder_path, exist_ok=True)

    global SUBDOMAINS_FILENAME
    fileDateFormat = "%Y%m%d_%H%M%S"
    SUBDOMAINS_FILENAME = f'{name}-{str(datetime.now().strftime(fileDateFormat))}.txt'

    global SUBDOMAINS_FILENAME_FULL_PATH
    SUBDOMAINS_FILENAME_FULL_PATH = SUBDOMAINS_FOLDER + '/' + SUBDOMAINS_FILENAME

    full_path = Path(SUBDOMAINS_FILENAME_FULL_PATH)
    if not os.path.exists(full_path):
        full_path.touch(exist_ok=True)


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
        print_error("Domain format not valid.")
        return

    banner_box('BUG BOUNTY', 'Automating Subdomain Discovery & Scanning')

    print_info(f'Setting up directories')
    run_directory_setup(name=args.domain)

    print_ok(f'target: {args.domain}')
    print_info(f'Enumerating subdomains with subfinder, assetfinder, and amass.')
    stdout, _ = run_subdomain_discovery(domain=args.domain)

    print_info(f"Using httpx to check for alive hosts.")
    hosts = check_alive_hosts(stdout)
    print(hosts)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warn('CTRL + C signal received. Exiting program...')
    except Exception as e:
        print_error(f'An error occurred: {type(e).__name__} - {e}')
