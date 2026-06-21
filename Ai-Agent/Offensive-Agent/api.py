from typing import Optional

from .core.config import AppConfig, load_config
from .core.orchestrator import Orchestrator
from .core.types import VulnType
from .models.schemas import Credentials, ScanRequest, ScanResult
from .utils.logger import get_logger
from .utils.rag import RAGEngine

logger = get_logger("api")


class OffensiveEngine:
    """
    Main entry point for the Offensive AI Agent.

    Usage (standalone):
        engine = OffensiveEngine()
        result = engine.scan("http://target.com", username="admin", password="password")

    Usage (BINGO integration):
        from final_result import OffensiveEngine
        engine = OffensiveEngine(config_path="/path/to/config.yaml")
        result = engine.scan(url, username=u, password=p, vuln_types=["sqli", "xss"])
    """

    def __init__(self, config_path: str = None, config: AppConfig = None):
        if config:
            self.config = config
        else:
            self.config = load_config(config_path)
        self.orchestrator = Orchestrator(self.config)
        self._ingested = False

    def set_human_callback(self, callback):
        """Register a callback(vuln_type, question) -> answer for human-in-the-loop questions."""
        self.orchestrator.human_callback = callback

    def ingest_knowledge_base(self, path: str = None) -> int:
        """One-time: embed the knowledge base into ChromaDB. Returns chunk count."""
        count = self.orchestrator.rag_engine.ingest(path)
        self._ingested = True
        return count

    def scan(
        self,
        url: str,
        username: str = "",
        password: str = "",
        cookies: dict = None,
        headers: dict = None,
        vuln_types: list[str] = None,
        scan_level: int = 2,
        cancel_event=None,
    ) -> ScanResult:
        """
        Run a full security scan against the target URL.

        Args:
            url: Target URL to scan.
            username: Login username (optional).
            password: Login password (optional).
            cookies: Session cookies dict (optional).
            headers: Extra HTTP headers dict (optional).
            vuln_types: List of vuln type strings to test (None = auto-detect all).

        Returns:
            ScanResult with findings, confidence scores, and metadata.
        """
        if not self._ingested:
            try:
                self.ingest_knowledge_base()
            except Exception as e:
                logger.warning(f"Knowledge base ingestion failed: {e}")

        credentials = None
        if username or password or cookies or headers:
            credentials = Credentials(
                username=username,
                password=password,
                cookies=cookies or {},
                headers=headers or {},
            )

        vt_enums = None
        if vuln_types:
            vt_enums = []
            for vt in vuln_types:
                try:
                    vt_enums.append(VulnType(vt))
                except ValueError:
                    logger.warning(f"Unknown vuln type: {vt}, skipping")

        request = ScanRequest(
            url=url,
            credentials=credentials,
            vuln_types=vt_enums,
            scan_level=scan_level or 2,
        )

        return self.orchestrator.scan(request, cancel_event=cancel_event)

    def scan_request(self, request: ScanRequest, cancel_event=None) -> ScanResult:
        """Run scan from a pre-built ScanRequest (for advanced integration)."""
        if not self._ingested:
            try:
                self.ingest_knowledge_base()
            except Exception as e:
                logger.warning(f"Knowledge base ingestion failed: {e}")
        return self.orchestrator.scan(request, cancel_event=cancel_event)

    def get_config(self) -> AppConfig:
        """Return current configuration (for inspection/debugging)."""
        return self.config
