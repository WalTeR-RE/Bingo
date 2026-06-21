from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from ..core.types import Confidence, Severity, VulnType


# --- Request Models ---

class Credentials(BaseModel):
    username: str = ""
    password: str = ""
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    url: str
    credentials: Optional[Credentials] = None
    vuln_types: Optional[list[VulnType]] = None  # None = scan all
    scan_level: int = 2  # 1 = fast, 2 = deep (default), 3 = ultimate
    config_overrides: dict = Field(default_factory=dict)


# --- Agent Output Models ---

class ReconOutput(BaseModel):
    target_url: str = ""
    ip_address: str = ""
    open_ports: list[dict] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    directories: list[str] = Field(default_factory=list)
    http_methods: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    robots_txt: str = ""
    sitemap: list[str] = Field(default_factory=list)
    raw_output: str = ""


class FormInfo(BaseModel):
    action: str = ""
    method: str = "GET"
    inputs: list[dict] = Field(default_factory=list)
    page_url: str = ""  # the page this form was found on


class WebAnalysisOutput(BaseModel):
    url: str = ""
    title: str = ""
    forms: list[FormInfo] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)
    scripts: list[str] = Field(default_factory=list)
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    page_text: str = ""
    raw_html: str = ""


class DiscoveryFinding(BaseModel):
    vuln_type: str = ""
    location: str = ""
    parameter: str = ""
    evidence: str = ""
    priority: str = "medium"


class AttackSurface(BaseModel):
    """Structured attack surface info for OpenAI Structured Outputs compatibility."""
    forms: list[str] = Field(default_factory=list)
    input_fields: list[str] = Field(default_factory=list)
    api_endpoints: list[str] = Field(default_factory=list)
    authentication: list[str] = Field(default_factory=list)
    file_uploads: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class DiscoveryOutput(BaseModel):
    potential_vulns: list[DiscoveryFinding] = Field(default_factory=list)
    attack_surface: AttackSurface = Field(default_factory=AttackSurface)
    technology_stack: list[str] = Field(default_factory=list)


class RouterOutput(BaseModel):
    vuln_types: list[str] = Field(default_factory=list)
    reasoning: str = ""


class PlanStep(BaseModel):
    step_number: int = 0
    action: str = ""
    tool: str = ""
    command: str = ""
    expected_outcome: str = ""


class AttackPlan(BaseModel):
    vuln_type: str = ""
    target_url: str = ""
    parameter: str = ""
    steps: list[PlanStep] = Field(default_factory=list)
    fallback_steps: list[PlanStep] = Field(default_factory=list)


# --- Result Models ---

class VulnerabilityFinding(BaseModel):
    vuln_type: VulnType = VulnType.OTHER
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.UNVERIFIED
    url: str = ""
    parameter: str = ""
    payload: str = ""
    poc_url: str = ""
    evidence: str = ""
    reproduction_steps: list[str] = Field(default_factory=list)
    tool_output: str = ""
    recommendations: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    target_url: str = ""
    scan_id: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)
    duration_seconds: float = 0.0
    recon_summary: Optional[ReconOutput] = None
    web_analysis: Optional[WebAnalysisOutput] = None
    discovery: Optional[DiscoveryOutput] = None
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def confirmed_vulns(self) -> list[VulnerabilityFinding]:
        return [f for f in self.findings if f.confidence == Confidence.CONFIRMED]

    def get_summary(self) -> str:
        total = len(self.findings)
        confirmed = len(self.confirmed_vulns)
        by_severity: dict[str, int] = {}
        for f in self.findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        return (
            f"Scan of {self.target_url}: "
            f"{total} findings ({confirmed} confirmed). "
            f"Severity breakdown: {by_severity}"
        )
