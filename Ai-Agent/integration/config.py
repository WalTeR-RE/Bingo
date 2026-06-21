"""
Integration configuration — shared settings for all Bingo agents.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class WebsiteConfig:
    """Connection settings for the Bingo Reporting Website API."""
    base_url: str = "http://localhost:8000/api"
    access_token: str = ""


@dataclass
class OffensiveConfig:
    """Settings for the Offensive Agent integration."""
    config_path: str = ""
    enabled: bool = True


@dataclass
class DefensiveConfig:
    """Settings for the Defensive Agent integration."""
    model_path: str = ""
    enabled: bool = True
    proxy_port: int = 8080
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 4280
    block_threats: bool = True
    threat_threshold: float = 0.70


@dataclass
class IntegrationConfig:
    """Top-level integration config combining all agent settings."""
    website: WebsiteConfig = field(default_factory=WebsiteConfig)
    offensive: OffensiveConfig = field(default_factory=OffensiveConfig)
    defensive: DefensiveConfig = field(default_factory=DefensiveConfig)


def load_integration_config(config_path: str = None) -> IntegrationConfig:
    """
    Load integration config from YAML file + environment variable overrides.

    Looks for 'integration_config.yaml' in the Ai-Agent/ directory by default.
    Environment variables:
        BINGO_API_URL       — website base URL
        BINGO_ACCESS_TOKEN  — agent access token (bingo_ak_...)
        WAF_MODEL_PATH      — path to waf_model.pkl
        WAF_PROXY_PORT      — WAF proxy listen port (default 8080)
        WAF_UPSTREAM_PORT   — upstream target port  (default 4280)
    """
    data = {}

    if config_path is None:
        default_path = Path(__file__).parent.parent / "integration_config.yaml"
        if default_path.exists():
            config_path = str(default_path)

    if config_path and Path(config_path).exists():
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

    website_data = data.get("website", {})
    offensive_data = data.get("offensive", {})
    defensive_data = data.get("defensive", {})

    config = IntegrationConfig(
        website=WebsiteConfig(
            base_url=os.getenv("BINGO_API_URL", website_data.get("base_url", "http://localhost:8000/api")),
            access_token=os.getenv("BINGO_ACCESS_TOKEN", website_data.get("access_token", "")),
        ),
        offensive=OffensiveConfig(
            config_path=offensive_data.get("config_path", ""),
            enabled=offensive_data.get("enabled", True),
        ),
        defensive=DefensiveConfig(
            model_path=os.getenv("WAF_MODEL_PATH", defensive_data.get("model_path", "")),
            enabled=defensive_data.get("enabled", True),
            proxy_port=int(os.getenv("WAF_PROXY_PORT", defensive_data.get("proxy_port", 8080))),
            upstream_host=defensive_data.get("upstream_host", "127.0.0.1"),
            upstream_port=int(os.getenv("WAF_UPSTREAM_PORT", defensive_data.get("upstream_port", 4280))),
            block_threats=defensive_data.get("block_threats", True),
            threat_threshold=defensive_data.get("threat_threshold", 0.70),
        ),
    )

    base_dir = Path(config_path).parent if config_path else Path(__file__).parent.parent
    if config.offensive.config_path and not Path(config.offensive.config_path).is_absolute():
        config.offensive.config_path = str((base_dir / config.offensive.config_path).resolve())
    if config.defensive.model_path and not Path(config.defensive.model_path).is_absolute():
        config.defensive.model_path = str((base_dir / config.defensive.model_path).resolve())

    return config
