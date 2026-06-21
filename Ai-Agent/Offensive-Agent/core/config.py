import os
from pathlib import Path

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field


class ModelConfig(BaseModel):
    router: str = "gpt-4o"
    planner: str = "gpt-4o"
    exploit: str = "gpt-4o"
    recon: str = "gpt-4o-mini"
    discovery: str = "gpt-4o-mini"
    summarizer: str = "gpt-4o-mini"
    embeddings: str = "text-embedding-3-small"


class WordlistPaths(BaseModel):
    common: str = "/usr/share/wordlists/dirb/common.txt"
    rockyou: str = "/usr/share/wordlists/rockyou.txt"
    dns: str = "/usr/share/wordlists/dns/subdomains-top1million-5000.txt"


class PathConfig(BaseModel):
    knowledge_base: str = "../knowledge_base"
    chroma_db: str = "./chroma_db"
    output_dir: str = "./output"
    wordlists: WordlistPaths = Field(default_factory=WordlistPaths)


class AgentLimitsConfig(BaseModel):
    recon_timeout: int = 300
    exploit_max_iterations: int = 15
    exploit_max_seconds: int = 240
    discovery_timeout: int = 60
    planner_timeout: int = 60
    max_parallel_agents: int = 5
    command_timeout: int = 120
    max_output_length: int = 10000


class ReportingConfig(BaseModel):
    enabled: bool = False
    api_url: str = "http://localhost:8000/api"
    api_key: str = ""
    format: str = "json"


class AppConfig(BaseModel):
    openai_api_key: str = ""
    models: ModelConfig = Field(default_factory=ModelConfig)
    paths: PathConfig = Field(default_factory=PathConfig)
    agent_limits: AgentLimitsConfig = Field(default_factory=AgentLimitsConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)


def load_config(config_path: str = None) -> AppConfig:
    """Load config from YAML file + .env overrides."""
    load_dotenv()

    data = {}
    if config_path is None:
        default_path = Path(__file__).parent.parent / "config.yaml"
        if default_path.exists():
            config_path = str(default_path)

    if config_path and Path(config_path).exists():
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

    base_dir = Path(config_path).parent if config_path else Path.cwd()
    if "paths" in data:
        for key in ["knowledge_base", "chroma_db", "output_dir"]:
            if key in data["paths"]:
                p = Path(data["paths"][key])
                if not p.is_absolute():
                    data["paths"][key] = str((base_dir / p).resolve())

    data["openai_api_key"] = os.getenv("OPENAI_API_KEY", data.get("openai_api_key", ""))
    if "reporting" not in data:
        data["reporting"] = {}
    # Accept either REPORTING_API_KEY or BINGO_ACCESS_TOKEN as the agent token
    data["reporting"]["api_key"] = (
        os.getenv("REPORTING_API_KEY")
        or os.getenv("BINGO_ACCESS_TOKEN")
        or data.get("reporting", {}).get("api_key", "")
    )
    data["reporting"]["api_url"] = (
        os.getenv("REPORTING_API_URL")
        or os.getenv("BINGO_API_URL")
        or data.get("reporting", {}).get("api_url", "http://localhost:8000/api")
    )

    models = data.get("models") or {}
    all_override = os.getenv("OFFENSIVE_MODEL")
    for role in ("router", "planner", "exploit", "recon", "discovery", "summarizer"):
        specific = os.getenv(f"{role.upper()}_MODEL")
        if specific:
            models[role] = specific
        elif all_override:
            models[role] = all_override
    data["models"] = models

    return AppConfig(**data)
