import logging
import os
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

_configured = False
_lock = threading.Lock()
_ROOT = "bingo_offensive"
_FORMAT = "%(asctime)s | %(levelname)-8s | %(shortname)s | %(message)s"


class _ShortNameFilter(logging.Filter):
    def filter(self, record):
        record.shortname = record.name.split(".")[-1]
        return True


def _configure():
    global _configured
    if _configured:
        return
    with _lock:
        if _configured:
            return

        root = logging.getLogger(_ROOT)
        root.setLevel(logging.DEBUG)
        root.propagate = False
        for handler in list(root.handlers):
            root.removeHandler(handler)

        formatter = logging.Formatter(_FORMAT, datefmt="%H:%M:%S")
        name_filter = _ShortNameFilter()

        if os.getenv("BINGO_LOG_CONSOLE", "1") != "0":
            try:
                console = logging.StreamHandler(sys.stderr)
                console.setLevel(logging.INFO)
                console.setFormatter(formatter)
                console.addFilter(name_filter)
                root.addHandler(console)
            except Exception:
                pass

        try:
            Path("logs").mkdir(exist_ok=True)
            file_handler = RotatingFileHandler(
                "logs/offensive_agent.log",
                maxBytes=10 * 1024 * 1024,
                backupCount=7,
                encoding="utf-8",
                delay=True,
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            file_handler.addFilter(name_filter)
            root.addHandler(file_handler)
        except Exception:
            pass

        logging.getLogger("faiss").setLevel(logging.WARNING)
        logging.getLogger("faiss.loader").setLevel(logging.WARNING)

        _configured = True


def get_logger(name: str = None):
    _configure()
    return logging.getLogger(f"{_ROOT}.{name or 'main'}")


def console_print(message: str) -> None:
    """Print to stdout only when the logger's console sink is off (e.g. GUI subprocess),
    so important lines stay visible in the console without double-printing elsewhere."""
    if os.getenv("BINGO_LOG_CONSOLE", "1") == "0":
        try:
            print(message, flush=True)
        except Exception:
            pass
