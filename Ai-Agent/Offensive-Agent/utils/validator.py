import re

from ..core.types import Confidence
from ..models.schemas import VulnerabilityFinding
from ..utils.logger import get_logger

logger = get_logger("validator")


class Validator:
    """Deterministic, non-LLM verification of vulnerability findings."""

    def validate(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        validators = {
            "sqli": self._validate_sqli,
            "xss": self._validate_xss,
            "command_injection": self._validate_cmdi,
            "lfi": self._validate_lfi,
            "ssrf": self._validate_ssrf,
            "ssti": self._validate_ssti,
        }
        fn = validators.get(finding.vuln_type.value)
        if fn:
            return fn(finding)
        return finding

    def validate_all(
        self, findings: list[VulnerabilityFinding]
    ) -> list[VulnerabilityFinding]:
        validated = []
        for f in findings:
            try:
                validated.append(self.validate(f))
            except Exception as e:
                logger.warning(f"Validation error for {f.vuln_type}: {e}")
                validated.append(f)
        return validated

    # --- Per-vuln validators ---

    def _validate_sqli(self, f: VulnerabilityFinding) -> VulnerabilityFinding:
        patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*\bmysql_",
            r"Unclosed quotation mark",
            r"PostgreSQL.*ERROR",
            r"ORA-\d{5}",
            r"sqlite3\.OperationalError",
            r"ODBC.*SQL Server",
            r"sqlmap.*identified the following injection",
            r"Parameter.*is vulnerable",
            r"Type:\s*(boolean-based|time-based|UNION|error-based|stacked)",
        ]
        if self._match_any(f.evidence, patterns) or self._match_any(
            f.tool_output, patterns
        ):
            f.confidence = Confidence.CONFIRMED
        return f

    def _validate_xss(self, f: VulnerabilityFinding) -> VulnerabilityFinding:
        if f.payload and f.evidence:
            # Payload appears unescaped in response
            if f.payload in f.evidence:
                encoded = f.payload.replace("<", "&lt;").replace(">", "&gt;")
                if encoded not in f.evidence:
                    f.confidence = Confidence.CONFIRMED
                    return f
            # Dalfox POC
            if "[POC]" in f.tool_output or "[V]" in f.tool_output:
                f.confidence = Confidence.CONFIRMED
        return f

    def _validate_cmdi(self, f: VulnerabilityFinding) -> VulnerabilityFinding:
        patterns = [
            r"uid=\d+.*gid=\d+",
            r"root:.*:0:0:",
            r"Linux \S+ \d+\.\d+",
            r"Windows.*\d+\.\d+",
            r"commix.*identified.*injection point",
        ]
        if self._match_any(f.evidence, patterns) or self._match_any(
            f.tool_output, patterns
        ):
            f.confidence = Confidence.CONFIRMED
        return f

    def _validate_lfi(self, f: VulnerabilityFinding) -> VulnerabilityFinding:
        patterns = [
            r"root:.*:0:0:",
            r"\[fonts\]",
            r"<\?php",
            r"DB_PASSWORD",
            r"APP_KEY=",
        ]
        if self._match_any(f.evidence, patterns):
            f.confidence = Confidence.CONFIRMED
        return f

    def _validate_ssrf(self, f: VulnerabilityFinding) -> VulnerabilityFinding:
        patterns = [
            r"ami-[a-f0-9]+",  # AWS AMI ID
            r"iam/security-credentials",
            r"instance-identity",
            r"metadata.*computeMetadata",
        ]
        if self._match_any(f.evidence, patterns):
            f.confidence = Confidence.CONFIRMED
        elif "interactsh" in f.tool_output.lower() or "callback" in f.evidence.lower():
            f.confidence = Confidence.LIKELY
        return f

    def _validate_ssti(self, f: VulnerabilityFinding) -> VulnerabilityFinding:
        # Check if mathematical evaluation happened (49 from 7*7)
        if "49" in f.evidence and ("7*7" in f.payload or "7*7" in f.evidence):
            f.confidence = Confidence.CONFIRMED
        elif any(
            x in f.tool_output
            for x in ["uid=", "root:", "os.popen", "RCE confirmed"]
        ):
            f.confidence = Confidence.CONFIRMED
        return f

    @staticmethod
    def _match_any(text: str, patterns: list[str]) -> bool:
        if not text:
            return False
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)
