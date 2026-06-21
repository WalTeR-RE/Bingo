import threading
from typing import Any

from ..utils.logger import get_logger

logger = get_logger("memory")


class SharedMemory:
    """Thread-safe shared state store for cross-agent communication."""

    def __init__(self):
        self._store: dict[str, Any] = {}
        self._lock = threading.Lock()

    def set(self, key: str, value: Any):
        with self._lock:
            self._store[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._store.get(key, default)

    def append(self, key: str, value: Any):
        with self._lock:
            if key not in self._store:
                self._store[key] = []
            self._store[key].append(value)

    def get_all(self) -> dict:
        with self._lock:
            return dict(self._store)

    # --- Typed accessors ---

    def set_recon(self, output):
        self.set("recon_output", output)

    def get_recon(self):
        return self.get("recon_output")

    def set_web_analysis(self, output):
        self.set("web_analysis", output)

    def get_web_analysis(self):
        return self.get("web_analysis")

    def set_discovery(self, output):
        self.set("discovery_output", output)

    def get_discovery(self):
        return self.get("discovery_output")

    def add_finding(self, finding):
        self.append("findings", finding)

    def get_findings(self) -> list:
        return self.get("findings", [])

    def add_error(self, error: str):
        self.append("errors", error)

    def get_errors(self) -> list[str]:
        return self.get("errors", [])

    def set_credentials(self, creds):
        self.set("credentials", creds)

    def get_credentials(self):
        return self.get("credentials")

    def clear(self):
        with self._lock:
            self._store.clear()
