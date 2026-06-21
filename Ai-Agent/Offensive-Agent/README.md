# Offensive-Agent

Autonomous reconnaissance-to-exploitation pipeline for Bingo, built as a LangChain ReAct agent swarm that maps a target's attack surface, plans per-vulnerability attacks, executes real tools, and validates findings deterministically.

## What it does

Given a target URL (plus optional credentials), the engine runs a six-phase pipeline and returns structured, confidence-scored findings:

1. **Recon + Web analysis** (parallel) — infrastructure recon via shell tools and a Playwright crawl that extracts forms, links, headers, and cookies across same-origin pages.
2. **Discovery** — an LLM identifies candidate vulnerabilities from the recon and crawl data.
3. **Surface expansion** — discovery findings are enriched with concrete endpoints, augmented by tool-free active discovery (hidden paths/parameters) and an optional known-app profile, then mapped to a full `(vuln_type, endpoint, parameter)` injection-point inventory.
4. **Routing** — selects which vulnerability types to test.
5. **Planning + Exploitation** (parallel, two-phase) — a planner builds an attack plan per type; ReAct exploit agents execute it with RAG-retrieved technique/tool knowledge. A completeness critic re-runs untested surfaces for the configured number of rounds.
6. **Validation + Reporting** — deterministic, non-LLM validators confirm evidence; results are saved locally and (optionally) pushed to the Bingo platform API.

Any files the scan writes to the working directory (webshells, cookie jars, downloaded payloads, tool output) are cleaned up automatically afterward unless `BINGO_KEEP_ARTIFACTS=1` is set.

## How it fits into Bingo

This folder is the offensive engine. A scan reaches it via:

```
integration/dispatcher.py → scan_runner.py (subprocess) → OffensiveEngine.scan → Orchestrator.scan
```

Voice/GUI scans and headless scans share this path. See the [root README](../../README.md) and `CLAUDE.md` for stack setup, Docker, and DVWA lab details.

## Entry points

```python
from api import OffensiveEngine

engine = OffensiveEngine()                       # loads config.yaml + .env
result = engine.scan(
    "http://localhost:4280",
    username="admin", password="password",
    vuln_types=["sqli", "xss"],                  # None = auto-detect all
    scan_level=2,                                # 1=fast, 2=default, 3=deep
)
```

- **`api.py`** — `OffensiveEngine`, the standalone/integration entry point. Auto-ingests the knowledge base on first scan; `set_human_callback(...)` registers a human-in-the-loop answerer.
- **`scan_runner.py`** — subprocess entry used by the platform. Reads a JSON job file (`params`, `result_file`, optional `cancel_file`/`progress_file`/`config_path`), runs the scan, and writes a summarized JSON result. Supports file-based cancellation.

## Layout

| Path | Responsibility |
| --- | --- |
| `api.py` | `OffensiveEngine` entry point (standalone + integration) |
| `scan_runner.py` | Subprocess entry; JSON job in, JSON result out; file-based cancel |
| `core/orchestrator.py` | The pipeline: recon → discovery → route → plan → exploit → validate → report; auto-login, surface expansion, parallel waves, completeness critic, artifact cleanup |
| `core/surface.py` | Maps the crawled surface to a target-agnostic injection-point inventory |
| `core/active_discovery.py` | Tool-free discovery of hidden endpoints and parameters (level-scaled) |
| `core/profiles.py` | Known-application accelerators (seed findings + cheat-sheets); never replaces discovery |
| `core/config.py` | `AppConfig` / `load_config` — YAML + `.env` overrides |
| `core/types.py` | `VulnType`, `Severity`, `Confidence`, `ScanPhase` enums |
| `agents/recon.py` | Infrastructure recon ReAct agent (shell tools) |
| `agents/discovery.py` | LLM vulnerability discovery from recon + web analysis |
| `agents/router.py` | Selects which vuln types to test |
| `agents/planner.py` | Builds per-type, step-by-step attack plans |
| `agents/base_exploit.py` | ReAct exploit agent (shell + Python REPL); permissive `STATUS:` parser, evidence markers |
| `agents/configs.py` | Per-vuln exploit configs (tool hints, iteration caps, prompt) |
| `web_analyzer/analyzer.py` | Playwright crawler — forms, links, headers, cookies |
| `utils/rag.py` | Hybrid RAG: FAISS (dense) + BM25 (sparse) fused with RRF, metadata-boosted |
| `utils/validator.py` | Deterministic, non-LLM finding validation per vuln type |
| `utils/reporter.py` | Local report save + platform API push (severity/CWE mapping) |
| `utils/memory.py` | `SharedMemory` shared across the pipeline |
| `utils/progress.py` | Progress reporting (writes `BINGO_PROGRESS_FILE`) |
| `prompts/templates.py` | Prompt templates for each agent role |
| `models/schemas.py` | Pydantic request/result/finding schemas |
| `knowledge_base/` | RAG source (Markdown: `vulnerabilities/`, `tools/`, `dvwa/`); ingested to FAISS on first scan |
| `config.yaml` | Default models, paths, wordlists, agent limits, reporting |

## Scan levels

`scan_level` (1–3) scales crawl depth, active-discovery budget, exploit iterations, completeness-critic retry rounds, and parallelism. Level 2 is the default.

## Configuration

`load_config()` reads `config.yaml` next to this folder, then applies `.env` overrides. Secrets live in `Ai-Agent/.env` (not here).

**Models** — every role defaults to `gpt-4o-mini` for rate-limit safety. Override one role with `<ROLE>_MODEL` (`ROUTER_MODEL`, `PLANNER_MODEL`, `EXPLOIT_MODEL`, `RECON_MODEL`, `DISCOVERY_MODEL`, `SUMMARIZER_MODEL`) or all at once with `OFFENSIVE_MODEL`. Lower `agent_limits.max_parallel_agents` if you switch to a model with a tighter TPM.

**Key environment variables**

| Variable | Purpose |
| --- | --- |
| `OPENAI_API_KEY` | LLM + embeddings (required) |
| `OFFENSIVE_MODEL` / `<ROLE>_MODEL` | Override model per role or globally |
| `REPORTING_API_KEY` / `BINGO_ACCESS_TOKEN` | Platform agent token (`bingo_ak_...`) |
| `REPORTING_API_URL` / `BINGO_API_URL` | Platform API base (default `http://localhost:8000/api`) |
| `BINGO_TARGET_PROFILE` | `dvwa` / `none` to force or disable profile auto-detect |
| `BINGO_KEEP_ARTIFACTS` | `1` keeps files the scan creates (default: cleaned up) |
| `BINGO_PROGRESS_FILE` | Path the engine writes phase progress to |

**Paths** (`config.yaml › paths`) — `knowledge_base` (RAG source), `chroma_db` (FAISS index lives in a sibling `faiss_index/`), `output_dir`, and optional SecLists `wordlists`. SecLists is optional; active discovery has a built-in path/parameter fallback.

## Knowledge base

`knowledge_base/` holds Markdown technique docs (`vulnerabilities/`, `tools/`, DVWA walkthroughs in `dvwa/`). On the first scan it is split, embedded with `text-embedding-3-small`, and persisted to a FAISS index alongside a BM25 sparse index; subsequent scans reuse the saved index. Add or edit `.md` files and re-ingest (`engine.ingest_knowledge_base()`) to extend coverage.
