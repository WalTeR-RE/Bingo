"""
Reporting Client — sends structured data to the Bingo Website API.

Handles both:
  - Offensive scan reports  → POST /agent/reports  (with vulnerabilities)
  - Defensive threat events → POST /agent/incidents
  - Agent heartbeats        → POST /agent/heartbeat
"""

import logging
from datetime import datetime, timezone

import httpx

from .config import IntegrationConfig
from .contracts import (
    HeartbeatPayload,
    IncidentPayload,
    ScanReportPayload,
    VulnerabilityPayload,
)

logger = logging.getLogger("bingo.reporting")

class ReportingClient:
    """HTTP client for the Bingo Reporting Website agent API."""

    def __init__(self, config: IntegrationConfig):
        self._base_url = config.website.base_url.rstrip("/")
        self._token = config.website.access_token
        self._timeout = 30

    @property
    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    @property
    def is_configured(self) -> bool:
        """True if both base URL and access token are set."""
        return bool(self._base_url and self._token)

    def send_heartbeat(
        self,
        agent_name: str,
        agent_type: str,
        status: str = "idle",
        metadata: dict = None,
    ) -> bool:
        """Send a heartbeat to let the website know the agent is alive."""
        if not self.is_configured:
            logger.warning("Reporting not configured (missing token/URL), skipping heartbeat")
            return False

        try:
            validated = HeartbeatPayload(
                agent_name=agent_name,
                agent_type=agent_type,
                status=status,
                metadata=metadata or {},
            )
        except Exception as e:
            logger.error("Heartbeat payload validation failed: %s", e)
            return False

        try:
            resp = httpx.post(
                f"{self._base_url}/agent/heartbeat",
                json=validated.model_dump(),
                headers=self._headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            logger.info("Heartbeat sent: %s (%s)", agent_name, status)
            return True
        except Exception as e:
            logger.error("Heartbeat failed: %s", e)
            return False

    def submit_scan_report(self, scan_result) -> dict:
        """
        Submit an offensive scan report (ScanResult) to the website.

        Transforms the ScanResult Pydantic model into the website's
        expected /agent/reports format, validates through ScanReportPayload
        contract, then sends.

        Returns the API response dict or {"error": "..."} on failure.
        """
        if not self.is_configured:
            logger.warning("Reporting not configured, skipping report submission")
            return {"error": "Reporting not configured"}

        severity_map = {
            "info": "informational",
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }

        cwe_map = {
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

        vulnerabilities = []
        for finding in scan_result.findings:
            vuln_type_str = finding.vuln_type.value if hasattr(finding.vuln_type, "value") else str(finding.vuln_type)
            severity_str = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            confidence_str = finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence)

            vulnerabilities.append(VulnerabilityPayload(
                name=f"{vuln_type_str.upper()} in {finding.parameter or finding.url}",
                severity=severity_map.get(severity_str, severity_str),
                description=(
                    f"Vulnerability type: {vuln_type_str}. "
                    f"Confidence: {confidence_str}. "
                    f"Parameter: {finding.parameter or 'N/A'}."
                ),
                affected_asset=finding.url,
                evidence=(finding.evidence or "")[:2000],
                remediation="; ".join(finding.recommendations) if finding.recommendations else None,
                cwe_id=cwe_map.get(vuln_type_str, ""),
            ))

        try:
            validated = ScanReportPayload(
                name=f"Offensive Scan — {scan_result.target_url}",
                target=scan_result.target_url,
                scan_type="Web Application",
                scan_date=(
                    scan_result.timestamp.strftime("%Y-%m-%d")
                    if scan_result.timestamp
                    else datetime.now(timezone.utc).strftime("%Y-%m-%d")
                ),
                notes=(
                    f"Scan ID: {scan_result.scan_id}. "
                    f"Duration: {scan_result.duration_seconds:.1f}s. "
                    f"{scan_result.get_summary()}"
                ),
                created_by="Bingo Agent (Offensive)",
                vulnerabilities=vulnerabilities,
            )
        except Exception as e:
            logger.error("Report payload validation failed: %s", e)
            return {"error": f"Payload validation failed: {e}"}

        try:
            resp = httpx.post(
                f"{self._base_url}/agent/reports",
                json=validated.model_dump(exclude_none=True),
                headers=self._headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info(
                "Report submitted: %s (vulns: %d)",
                result.get("report_id", "?"),
                result.get("vulnerabilities_count", 0),
            )
            return result
        except httpx.HTTPStatusError as e:
            body = e.response.text
            logger.error("Report submission failed [%d]: %s", e.response.status_code, body)
            return {"error": f"HTTP {e.response.status_code}: {body}"}
        except Exception as e:
            logger.error("Report submission failed: %s", e)
            return {"error": str(e)}

    def submit_threat_incident(self, threat_event) -> dict:
        """
        Submit a defensive threat event as an incident to the website.

        Accepts a ThreatEvent dataclass from the Defensive Agent.
        Validates through IncidentPayload contract before sending.

        Returns the API response dict or {"error": "..."} on failure.
        """
        if not self.is_configured:
            logger.warning("Reporting not configured, skipping incident submission")
            return {"error": "Reporting not configured"}

        severity_map = {
            "SQLi": "critical",
            "XSS": "high",
            "RCE": "critical",
            "LFI": "high",
            "RFI": "high",
        }

        prediction = threat_event.prediction if isinstance(threat_event.prediction, str) else str(threat_event.prediction)
        severity = severity_map.get(prediction, "medium")

        try:
            validated = IncidentPayload(
                title=f"{prediction} attack detected from {threat_event.source_ip}",
                description=(
                    f"WAF detected a {prediction} attack with {threat_event.confidence:.0%} confidence. "
                    f"Method: {threat_event.method}. URL: {threat_event.url}. "
                    f"Matched payload: {threat_event.matched_payload[:500]}"
                ),
                severity=severity,
                source_ip=threat_event.source_ip,
                affected_asset=threat_event.url,
                rule_triggered=f"WAF_{prediction.upper()}",
                raw_log=[
                    f"Timestamp: {threat_event.timestamp}",
                    f"Source: {threat_event.source_ip}:{threat_event.source_port}",
                    f"Method: {threat_event.method}",
                    f"URL: {threat_event.url}",
                    f"Payload: {threat_event.matched_payload}",
                    f"Prediction: {prediction} ({threat_event.confidence:.2%})",
                    f"Action: {threat_event.action}",
                ],
                detected_at=threat_event.timestamp,
                action_taken=threat_event.action,
            )
        except Exception as e:
            logger.error("Incident payload validation failed: %s", e)
            return {"error": f"Payload validation failed: {e}"}

        try:
            resp = httpx.post(
                f"{self._base_url}/agent/incidents",
                json=validated.model_dump(exclude_none=True),
                headers=self._headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info("Incident submitted: %s", result.get("incident_id", "?"))
            return result
        except httpx.HTTPStatusError as e:
            body = e.response.text
            logger.error("Incident submission failed [%d]: %s", e.response.status_code, body)
            return {"error": f"HTTP {e.response.status_code}: {body}"}
        except Exception as e:
            logger.error("Incident submission failed: %s", e)
            return {"error": str(e)}
