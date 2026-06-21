"""
Agent Contracts — Pydantic models that define the exact data format
exchanged between every pair of agents in the Bingo system.

These are the "schemas at the boundary": every piece of data that crosses
from one agent to another MUST be validated through one of these models.
If the data doesn't match, a ValidationError is raised immediately —
catching format mismatches before they cause silent downstream bugs.

Boundary Map:
  User Speech  →  IntentRouter   →  IntentResult         (voice → routing)
  IntentResult →  Dispatcher     →  OffensiveScanParams   (routing → offensive)
  IntentResult →  Dispatcher     →  DefensiveStartParams  (routing → defensive)
  Offensive    →  ReportingClient→  ScanReportPayload     (offensive → website)
  Defensive    →  ReportingClient→  IncidentPayload       (defensive → website)
  Both         →  ReportingClient→  HeartbeatPayload      (agents → website)
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator

class IntentCategory(str, Enum):
    OFFENSIVE = "offensive"
    DEFENSIVE_START = "defensive_start"
    DEFENSIVE_STOP = "defensive_stop"
    DEFENSIVE_STATUS = "defensive_status"
    SCAN_STATUS = "scan_status"
    CONVERSATION = "conversation"

class OffensiveParams(BaseModel):
    """Parameters extracted when intent = offensive."""
    url: str
    username: Optional[str] = None
    password: Optional[str] = None
    cookies: Optional[dict[str, str]] = None
    vuln_types: Optional[list[str]] = None
    security_level: Optional[str] = None
    scan_level: Optional[int] = None

    @field_validator("url")
    @classmethod
    def ensure_protocol(cls, v: str) -> str:
        v = v.strip()
        if v and not v.startswith(("http://", "https://")):
            v = f"http://{v}"
        return v

class DefensiveStartParams(BaseModel):
    """Parameters extracted when intent = defensive_start."""
    mode: str = "sniffer"
    upstream_host: Optional[str] = None
    upstream_port: Optional[int] = None
    loopback: bool = False
    port: Optional[int] = None

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        allowed = {"proxy", "sniffer"}
        if v not in allowed:
            return "proxy"
        return v

class IntentResult(BaseModel):
    """
    Structured output from the Intent Router.

    This is the contract between the voice layer and the dispatcher.
    The OpenAI Structured Output API guarantees this shape.
    """
    intent: IntentCategory
    params: dict = Field(default_factory=dict)

    def get_offensive_params(self) -> OffensiveParams:
        """Parse and validate params as OffensiveParams."""
        return OffensiveParams(**self.params)

    def get_defensive_start_params(self) -> DefensiveStartParams:
        """Parse and validate params as DefensiveStartParams."""
        return DefensiveStartParams(**self.params)

class VulnerabilityPayload(BaseModel):
    """Single vulnerability in a report — matches POST /agent/reports body."""
    name: str = Field(..., max_length=255)
    severity: str
    description: Optional[str] = None
    affected_asset: Optional[str] = Field(None, max_length=255)
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cwe_id: Optional[str] = Field(None, max_length=20)
    references: Optional[list[str]] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low", "informational"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {allowed}, got '{v}'")
        return v

class ScanReportPayload(BaseModel):
    """Full report payload — matches POST /agent/reports body."""
    name: str = Field(..., max_length=255)
    target: str = Field(..., max_length=255)
    scan_type: Optional[str] = Field("Web Application", max_length=50)
    scan_date: Optional[str] = None
    notes: Optional[str] = None
    created_by: Optional[str] = Field(None, max_length=100)
    vulnerabilities: list[VulnerabilityPayload] = Field(default_factory=list)

    @field_validator("scan_date")
    @classmethod
    def validate_date_format(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            datetime.strptime(v, "%Y-%m-%d")
        return v

class IncidentPayload(BaseModel):
    """Incident payload — matches POST /agent/incidents body."""
    title: str = Field(..., max_length=255)
    description: Optional[str] = None
    severity: str
    source_ip: Optional[str] = Field(None, max_length=45)
    destination_ip: Optional[str] = Field(None, max_length=45)
    affected_asset: Optional[str] = Field(None, max_length=255)
    rule_triggered: Optional[str] = Field(None, max_length=255)
    raw_log: Optional[list[str]] = None
    detected_at: Optional[str] = None
    action_taken: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low", "informational"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {allowed}, got '{v}'")
        return v

class HeartbeatPayload(BaseModel):
    """Heartbeat payload — matches POST /agent/heartbeat body."""
    agent_name: str
    agent_type: str
    status: str
    metadata: dict = Field(default_factory=dict)

    @field_validator("agent_type")
    @classmethod
    def validate_agent_type(cls, v: str) -> str:
        allowed = {"offensive", "defensive"}
        if v not in allowed:
            raise ValueError(f"agent_type must be one of {allowed}, got '{v}'")
        return v

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        allowed = {"idle", "scanning", "monitoring", "error"}
        if v not in allowed:
            raise ValueError(f"status must be one of {allowed}, got '{v}'")
        return v
