import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from ..models.schemas import ScanResult
from ..utils.logger import get_logger

logger = get_logger("reporter")

# Map offensive severity values to website API expected values
_SEVERITY_MAP = {
    "info": "informational",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

# Best-effort vuln_type → CWE mapping
_CWE_MAP = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "lfi": "CWE-98",
    "rfi": "CWE-98",
    "ssrf": "CWE-918",
    "csrf": "CWE-352",
    "command_injection": "CWE-78",
    "file_upload": "CWE-434",
    "brute_force": "CWE-307",
    "ssti": "CWE-1336",
    "xxe": "CWE-611",
    "idor": "CWE-639",
    "open_redirect": "CWE-601",
    "insecure_deserialization": "CWE-502",
    "authentication_bypass": "CWE-287",
    "race_condition": "CWE-362",
    "misconfiguration": "CWE-16",
}


class Reporter:
    """Handles reporting scan results — local file + remote API."""

    def __init__(self, config):
        self.enabled = config.reporting.enabled
        self.api_url = config.reporting.api_url.rstrip("/")
        self.api_key = config.reporting.api_key
        self.format = config.reporting.format

    def report(self, result: ScanResult) -> bool:
        """Send report to the Bingo Website /agent/reports endpoint. Returns True on success."""
        if not self.enabled:
            logger.info("Remote reporting disabled, skipping")
            return False

        if not self.api_key:
            logger.warning("Reporting API key not set, skipping")
            return False

        try:
            payload = self._build_website_payload(result)
            response = httpx.post(
                f"{self.api_url}/agent/reports",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=30,
            )
            response.raise_for_status()
            resp_data = response.json()
            logger.info(
                "Report submitted successfully: report_id=%s, vulns=%d",
                resp_data.get("report_id", "?"),
                resp_data.get("vulnerabilities_count", 0),
            )
            return True
        except Exception as e:
            logger.error(f"Remote reporting failed: {e}")
            return False

    def _build_website_payload(self, result: ScanResult) -> dict:
        """Transform ScanResult into the website's /agent/reports format."""
        vulnerabilities = []
        for finding in result.findings:
            vt = finding.vuln_type.value if hasattr(finding.vuln_type, "value") else str(finding.vuln_type)
            sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            conf = finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence)

            vuln = {
                "name": f"{vt.upper()} in {finding.parameter or finding.url}",
                "severity": _SEVERITY_MAP.get(sev, sev),
                "description": (
                    f"Vulnerability type: {vt}. Confidence: {conf}. "
                    f"Parameter: {finding.parameter or 'N/A'}. "
                    f"URL: {finding.url}."
                ),
                "affected_asset": finding.url,
                "evidence": (finding.evidence or "")[:2000],
                "payload": finding.payload or "",
                "cwe_id": _CWE_MAP.get(vt, ""),
            }
            refs = []
            if getattr(finding, "poc_url", ""):
                refs.append(finding.poc_url)
            cwe = _CWE_MAP.get(vt, "")
            if cwe:
                refs.append(f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html")
            if refs:
                vuln["references"] = refs
            if finding.recommendations:
                vuln["remediation"] = "; ".join(finding.recommendations)
            vulnerabilities.append(vuln)

        started = result.timestamp or datetime.now(timezone.utc)
        completed = started + timedelta(seconds=result.duration_seconds or 0)

        return {
            "name": f"Offensive Scan — {result.target_url}",
            "target": result.target_url,
            "scan_date": started.strftime("%Y-%m-%d"),
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "notes": (
                f"Scan ID: {result.scan_id}. "
                f"Duration: {result.duration_seconds:.1f}s. "
                f"{result.get_summary()}"
            ),
            "created_by": "Bingo Agent (Offensive)",
            "vulnerabilities": vulnerabilities,
        }

    def save_local(self, result: ScanResult, filepath: str = None) -> str:
        """Save report as JSON file. Returns the filepath."""
        if filepath is None:
            output_dir = Path("./output")
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = result.timestamp.strftime("%Y%m%d_%H%M%S")
            filepath = str(output_dir / f"scan_{timestamp}.json")

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result.model_dump(mode="json"), f, indent=2, default=str)

        logger.info(f"Report saved to {filepath}")
        return filepath
