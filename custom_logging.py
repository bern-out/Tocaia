from datetime import datetime
from enum import Enum
import threading

class LogLevel(Enum):
    INFO = 'INFO'
    WARN = 'WARN'
    ERROR = 'ERROR'
    OK = 'OK'


class CustomLogger:
    _lock = threading.Lock()

    _colors = {
        LogLevel.INFO:  '\033[94m',
        LogLevel.WARN:  '\033[93m',
        LogLevel.ERROR: '\033[91m',
        LogLevel.OK:    '\033[92m',
    }


    def __init__(self, domain: str = ''):
        self.__domain = domain


    def _emit(self, level: LogLevel, message: str):
        date_format = "%Y-%m-%d %H:%M:%S"
        ts = datetime.now().strftime(date_format)
        prefix = f"[{self.__domain}] " if self.__domain else ""
        color = self._colors[level]
        line = f"{color}{prefix}{level.value} [{ts}] {message}\033[0m"

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
