"""
Bingo Integration Layer — connects Behavioral, Offensive, and Defensive agents
with the Reporting Website API.
"""

from .config import IntegrationConfig, load_integration_config
from .contracts import (
    IntentCategory,
    IntentResult,
    OffensiveParams,
    DefensiveStartParams,
    ScanReportPayload,
    VulnerabilityPayload,
    IncidentPayload,
    HeartbeatPayload,
)
from .reporting_client import ReportingClient
from .intent_router import IntentRouter
from .dispatcher import AgentDispatcher

__all__ = [
    "IntegrationConfig",
    "load_integration_config",
    "IntentCategory",
    "IntentResult",
    "OffensiveParams",
    "DefensiveStartParams",
    "ScanReportPayload",
    "VulnerabilityPayload",
    "IncidentPayload",
    "HeartbeatPayload",
    "ReportingClient",
    "IntentRouter",
    "AgentDispatcher",
]
