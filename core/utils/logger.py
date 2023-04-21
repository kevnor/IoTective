from enum import Enum
import logging
from rich.logging import RichHandler
from rich.console import Console


class LogLevel(Enum):
    INFO = "info"
    ERROR = "error"
    WARNING = "warning"
    SUCCESS = "success"


class Logger:
    def __init__(self, console: Console) -> None:
        logging.basicConfig(
            format="%(message)s",
            level=logging.INFO,
            datefmt="[%X]",
            handlers=[RichHandler(console=console)],
        )

        RichHandler.KEYWORDS = ["[+]", "[-]", "[*]"]

        self.log = logging.getLogger("rich")

    def logger(self, level: LogLevel, message: str) -> None:
        if level == LogLevel.INFO:
            self.log.info(f"[+] {message}")
        elif level == LogLevel.ERROR:
            self.log.error(f"[-] {message}")
        elif level == LogLevel.WARNING:
            self.log.warning(f"[*] {message}")
        elif level == LogLevel.SUCCESS:
            self.log.info(f"[+] {message}")
