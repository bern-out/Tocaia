from datetime import datetime
from enum import Enum
import threading

class LogLevel(Enum):
    INFO = 'INFO'
    WARN = 'WARN'
    ERROR = 'ERROR'
    OK = 'OK'
    DEFAULT = 'DEFAULT'
    BOLD    = 'BOLD'
    UNDERLINE = 'UNDERLINE'


class CustomLogger:
    _lock = threading.Lock()

    _colors = {
        LogLevel.INFO:      '\033[94m',
        LogLevel.WARN:      '\033[93m',
        LogLevel.ERROR:     '\033[91m',
        LogLevel.OK:        '\033[92m',
        LogLevel.DEFAULT:   '\033[0m',
        LogLevel.BOLD:      '\033[1m',
        LogLevel.UNDERLINE: '\033[4m',
    }


    def __init__(self, domain: str = ''):
        self.__domain = domain


    def _emit(self, level: LogLevel, message: str):
        date_format = "%Y-%m-%d %H:%M:%S"
        ts = datetime.now().strftime(date_format)
        prefix = f"[{self.__domain}] " if self.__domain else ""
        color = self._colors[level]
        reset = self._colors[LogLevel.DEFAULT]
        bold = self._colors[LogLevel.BOLD]
        line = f"{prefix}{color}{level.value}{reset} {bold}[{ts}]{reset} {message}{reset}"

        with self._lock:
            print(line)

    def info(self, message: str):
        self._emit(LogLevel.INFO, message)

    def warn(self, message: str):
        self._emit(LogLevel.WARN, message)

    def error(self, message: str):
        self._emit(LogLevel.ERROR, message)

    def ok(self, message: str):
        self._emit(LogLevel.OK, message)
