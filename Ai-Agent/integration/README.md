# integration

Glue layer that connects Bingo's three agents (Behavioral, Offensive, Defensive) to each other and to the Laravel platform API.

## What this does

The behavioral agent never talks to the offensive or defensive engines directly, and it never builds raw HTTP payloads for the dashboard. Everything crosses through this package:

1. **Intent routing** — user speech/text is classified into one structured intent (`intent_router.py`).
2. **Dispatch** — the intent is validated and run asynchronously against the right engine (`dispatcher.py`): offensive scans launch as isolated subprocesses, the defensive WAF runs in-process.
3. **Reporting** — scan reports, threat incidents, and heartbeats are pushed to the platform API with a `bingo_ak_` bearer token (`reporting_client.py`).
4. **Contracts** — every value that crosses an agent boundary is validated against a Pydantic model (`contracts.py`), so format mismatches fail loudly at the edge instead of silently downstream.

It is consumed mainly by `Bingo_Agent.py` (voice/GUI loop) and shares the same scan path as headless runs. See the [root README](../../README.md) and `CLAUDE.md` for the system-wide picture.

## Files

| File | Responsibility |
| --- | --- |
| `__init__.py` | Public surface: re-exports config loader, contracts, `ReportingClient`, `IntentRouter`, `AgentDispatcher`. |
| `config.py` | `IntegrationConfig` dataclasses + `load_integration_config()` (YAML file + env-var overrides; resolves relative paths). |
| `contracts.py` | Pydantic boundary schemas — intents, scan/defensive params, and the website payloads (`ScanReportPayload`, `IncidentPayload`, `HeartbeatPayload`). |
| `intent_router.py` | `IntentRouter.classify()` — maps user text to a validated `IntentResult` using OpenAI Structured Outputs (`gpt-4o-mini`). |
| `dispatcher.py` | `AgentDispatcher` — async task management: starts/stops offensive scans (subprocess) and the WAF monitor, tracks task state, progress, and ETA. |
| `reporting_client.py` | `ReportingClient` — token-authenticated `httpx` POSTs to the platform's `/agent/*` endpoints. |

## Data flow (boundary map)

```
User speech  → IntentRouter    → IntentResult
IntentResult → AgentDispatcher → OffensiveParams      → Offensive-Agent/scan_runner.py (subprocess)
IntentResult → AgentDispatcher → DefensiveStartParams → Defensive-Agent WAFMonitor
Offensive    → ReportingClient → ScanReportPayload    → POST /agent/reports
Defensive    → ReportingClient → IncidentPayload      → POST /agent/incidents
Both         → ReportingClient → HeartbeatPayload     → POST /agent/heartbeat
```

## Key behaviors

- **Offensive scans run out-of-process.** `dispatcher.py` writes a `job.json` into a temp dir and runs `Offensive-Agent/scan_runner.py` as a subprocess, so a native crash can't take down the GUI. Cancellation is signalled via a `cancel.flag` file; live progress is read from a `progress.txt` file. The dispatcher exposes `get_scan_progress()` / `get_scans_summary()` (elapsed time, ETA, and a stuck-detection heuristic).
- **Heartbeats are sent from worker threads**, never the caller's thread, so a slow or down reporting endpoint can't block the voice loop.
- **Defensive monitor runs in-process** via the lazily imported `Defensive-Agent` package; threat events are reported as incidents through `_on_threat_detected`.
- **Intents are LLM-classified into a fixed enum**: `offensive`, `defensive_start`, `defensive_stop`, `defensive_status`, `scan_status`, `conversation`. The router prompt handles speech-to-text artifacts (e.g. spoken port numbers) and only populates the params object matching the chosen intent.

## Configuration

`load_integration_config()` reads `Ai-Agent/integration_config.yaml` (if present) and applies these environment overrides:

| Env var | Purpose |
| --- | --- |
| `BINGO_API_URL` | Platform API base URL (default `http://localhost:8000/api`). |
| `BINGO_ACCESS_TOKEN` | Agent auth token (`bingo_ak_...`). Reporting is skipped if unset. |
| `WAF_MODEL_PATH` | Path to `waf_model.pkl`. |
| `WAF_PROXY_PORT` | WAF proxy listen port (default `8080`). |
| `WAF_UPSTREAM_PORT` | Upstream target port (default `4280`). |

Relative `config_path` / `model_path` values are resolved against the config file's directory (or `Ai-Agent/` when no file is given).

## Usage

This package is imported, not run directly:

```python
from integration import (
    load_integration_config,
    ReportingClient,
    AgentDispatcher,
    IntentRouter,
)

config = load_integration_config()
reporter = ReportingClient(config)
dispatcher = AgentDispatcher(config, reporter)

task_id = dispatcher.start_offensive_scan({"url": "http://localhost:4280"})
```

`IntentRouter` requires an `openai.OpenAI` client; LLM roles default to `gpt-4o-mini`.
