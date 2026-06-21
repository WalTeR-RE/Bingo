# Ai-Agent

The three Bingo AI agents — Offensive (exploit swarm), Defensive (WAF), and Behavioral (voice/GUI assistant) — plus the integration layer that wires them to each other and to the Laravel dashboard, and the host/Docker entry-point scripts that drive them.

## What this is

`Ai-Agent/` is the Python side of Bingo. Everything an agent does and every report that reaches the dashboard originates here:

- **Offensive** — a LangChain ReAct recon→exploit pipeline (`Offensive-Agent/`).
- **Defensive** — an XGBoost-backed WAF engine and traffic monitor (`Defensive-Agent/`).
- **Behavioral** — a PyQt5 voice/GUI assistant (`Bingo_Agent.py` + `voice_io.py`) that turns speech into actions.
- **Integration** — schemas, intent routing, a non-blocking dispatcher, and the dashboard reporting client (`integration/`).

All LLM roles use `gpt-4o-mini`. STT/TTS/embeddings also go through OpenAI.

## Layout

| Path | Responsibility |
| --- | --- |
| `Offensive-Agent/` | Autonomous scan engine. `api.py` (`OffensiveEngine`) → `core/orchestrator.py`; `agents/` (recon, discovery, planner, router, exploit), `core/` (surface mapping, active discovery, target profiles, types). Run as a subprocess via `scan_runner.py`. |
| `Defensive-Agent/` | WAF. `waf_engine.py` (loads `waf_model.pkl`, classifies payloads), `waf_features.py` (char n-gram TF-IDF + statistical + regex features), `network_monitor.py` (reverse-proxy or scapy sniffer modes), `config.py`. |
| `integration/` | Cross-agent glue. `contracts.py` (Pydantic boundary schemas), `intent_router.py` (LLM intent classification via Structured Outputs), `dispatcher.py` (runs scans/monitor in background threads), `reporting_client.py` (POSTs reports/incidents/heartbeats to the API), `config.py`. |
| `Bingo_Agent.py` | Behavioral agent — PyQt5 GUI with continuous voice loop, intent routing, and spoken summaries. |
| `voice_io.py` | Low-latency mic capture (`webrtcvad` over a persistent PyAudio stream) and streaming TTS; import-safe with fallbacks. |
| `run_scan.py` | Quick local full-DVWA scan against `http://localhost:4280`. |
| `docker_scan.py` | Containerised end-to-end runner: bootstraps DVWA (create DB → login → set security), then scans. Configured via env vars (`TARGET`, `DVWA_USER`, `DVWA_PASS`, `DVWA_SECURITY`, `SCAN_VULN_TYPES`). |
| `bingo_headless.py` | No-GUI, no-voice text counterpart to `Bingo_Agent.py`; drives the same router→dispatcher→reporting pipeline for Docker/CI/scripting. |
| `run_waf.py` | Starts the defensive WAF reverse proxy in front of an upstream and keeps it alive, printing live stats. |
| `check_report.py` | Pretty-prints a saved scan JSON (`output/*.json`) — findings, discovery, web analysis, recon. |
| `integration_test.py` | Validates config, intent routing, reporting connectivity, and dispatcher lifecycle without voice I/O. |
| `integration_config.yaml` | Shared integration settings (website API URL/token, offensive config path, WAF model/proxy settings). |
| `requirements.txt` | Unified headless deps (LangChain stack, RAG, OpenAI, Playwright, WAF model). |
| `requirements-gui.txt` | Voice/GUI-only deps (PyQt5, pygame, PyAudio, SpeechRecognition, webrtcvad), pinned for Python 3.12. |
| `.env.example` | Template for `.env` (gitignored): `OPENAI_API_KEY`, `REPORTING_API_KEY`, optional `REPORTING_API_URL`. |
| `Dockerfile` | Image for the `agent` service used by the Docker workflow. |

## How a request flows

```
User speech / text
   → IntentRouter            (integration/intent_router.py)
   → AgentDispatcher         (integration/dispatcher.py, background thread)
       → Offensive-Agent/scan_runner.py (subprocess) → OffensiveEngine.scan → Orchestrator.scan
       → Defensive-Agent/network_monitor.py (WAF proxy/sniffer)
   → ReportingClient         (integration/reporting_client.py → dashboard API)
```

`Bingo_Agent.py` (voice/GUI) and `bingo_headless.py` (text) are interchangeable front-ends over this exact path.

## Configuration

Secrets live in `Ai-Agent/.env` (copy from `.env.example`). Behavior is tuned through `integration_config.yaml` and environment variables:

- **Dashboard / reporting** — `BINGO_API_URL` (→ `website.base_url`), `BINGO_ACCESS_TOKEN` (→ `website.access_token`; tokens start with `bingo_ak_`).
- **WAF** — `WAF_MODEL_PATH`, `WAF_PROXY_PORT`, `WAF_UPSTREAM_HOST`, `WAF_UPSTREAM_PORT`.
- **DVWA scan (docker_scan.py)** — `TARGET`, `DVWA_USER`, `DVWA_PASS`, `DVWA_SECURITY`, `SCAN_VULN_TYPES`.
- **Voice (Bingo_Agent.py)** — `BINGO_EOS_SILENCE_MS`, `BINGO_VAD_AGGRESSIVENESS`, `BINGO_STT_MODEL`, `BINGO_TTS_MODEL`, `BINGO_BARGE_IN`, `BINGO_DISABLE_VAD`, `BINGO_DISABLE_STREAM_TTS`.

The `Offensive-Agent/` (`config.yaml`) and `Defensive-Agent/` (`config.py`) hold their own per-engine settings.

## Running

Run from this directory with `.env` populated.

```bash
# Headless behavioral pipeline (text)
python bingo_headless.py --message "scan http://dvwa for sqli and xss" --wait
python bingo_headless.py --repl

# Direct offensive scans
python run_scan.py            # quick local DVWA scan
python docker_scan.py         # containerised end-to-end DVWA scan

# Defensive WAF proxy
python run_waf.py

# Behavioral GUI / voice assistant (needs requirements-gui.txt)
python Bingo_Agent.py
python Bingo_Agent.py --preview   # visuals only, no microphone

# Checks
python integration_test.py
python check_report.py
```

Headless/Docker runs only need `requirements.txt`; the voice/GUI assistant additionally needs `requirements-gui.txt` (and Npcap + admin rights for WAF sniffer mode).

See the repository root `README.md` for full environment setup and the Docker stack, and `../CLAUDE.md` for the project orientation.
