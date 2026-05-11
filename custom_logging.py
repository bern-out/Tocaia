class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_warn(msg: str):
    print(f'{bcolors.WARNING} [-] {msg}{bcolors.ENDC}')

def print_error(msg: str):
    print(f'{bcolors.FAIL} [-] {msg}{bcolors.ENDC}')

def print_ok(msg: str):
    print(f'{bcolors.OKGREEN} [+] {msg}{bcolors.ENDC}')

def print_info(msg: str):
    print(f'{bcolors.OKBLUE} [*] {msg}{bcolors.ENDC}')
