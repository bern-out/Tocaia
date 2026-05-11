#!/usr/bin/env python3
from pathlib import Path
import sys
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


def stream_output(pipe, target_stdin, lock: threading.Lock):
    try:
        for line in iter(pipe.readline, b''):
            with lock:
                target_stdin.write(line)
                target_stdin.flush()
    finally:
        pipe.close()


def run_subdomain_discovery(domain: str):
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
        stdout=subprocess.DEVNULL,
    )

    threads: list[threading.Thread] = []

    for cmd in commands:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        t = threading.Thread(
            target=stream_output,
            args=(p.stdout, p_tr.stdin)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    p_tr.stdin.close()
    p_anew.communicate()


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


def main():
    if len(sys.argv) < 2:
        print('Not enough arguments provided')
        print_usage()
        return

    domain = sys.argv[1]
    
    banner_box('BUG BOUNTY', 'Automating Subdomain Discovery & Scanning')

    print_info(f'Setting up directories')
    run_directory_setup(name=domain)

    print_ok(f'target: {domain}')
    print_info(f'Enumerating subdomains')
    run_subdomain_discovery(domain=domain)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warn('CTRL + C signal received. Exiting program...')
    except Exception as e:
        print_error(f'An error occurred: {type(e).__name__} - {e}')
