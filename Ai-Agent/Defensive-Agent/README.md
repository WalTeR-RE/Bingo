# Defensive-Agent

Machine-learning Web Application Firewall: a trained XGBoost classifier that inspects live web traffic and blocks or logs malicious requests.

## What it does

The defensive agent loads a pre-trained model (`waf_model.pkl`) and classifies each HTTP(S) request — method, URI, query string, and body — into a benign `Normal` class or one of several attack categories (SQLi, XSS, path traversal, RCE, RFI/SSRF, SSTI). Requests are URL-decoded (single and double) before inspection so encoded payloads are caught. When a threat scores at or above the configured confidence threshold, the monitor either returns `403` (proxy mode) or logs it (sniffer / log-only mode) and emits a `ThreatEvent`.

Within Bingo this is the **Defensive** pillar: where the offensive swarm attacks a target and the behavioral agent drives the system by voice/GUI, this module sits inline (or passively) in front of an application and is the runtime protection layer. An optional `on_threat(ThreatEvent)` callback lets a host process forward detections to the Laravel dashboard via `Ai-Agent/integration/`.

## How classification works

The feature pipeline in `waf_features.py` matches the training pipeline exactly, so the `.pkl` is the only artifact needed:

- **Char n-gram TF-IDF** over the request string (vectorizer is stored in the model file).
- **Statistical features** — length, special-char/digit/alpha/upper ratios, percent-encoding count, Shannon entropy, path depth, parameter count, SQL-keyword density, etc.
- **Per-category regex pattern counts and hit flags** for `sqli`, `xss`, `traversal`, `rce`, `rfi_ssrf`, and `ssti`.

`WAFEngine.analyze` applies a low-confidence guard: a predicted threat below `0.75` confidence is reverted to `Normal` if the benign probability is non-trivial and no regex attack signal is present, reducing false positives.

## Files

| File | Responsibility |
|------|----------------|
| `waf_engine.py` | `WAFEngine` — loads the model bundle (model, vectorizer, label encoder), runs prediction, and exposes `analyze`, `analyze_decoded`, `analyze_batch`. |
| `waf_features.py` | Feature extraction shared with training: TF-IDF + statistical features + regex category counts; `extract_features`, `compute_stats`, `any_attack_signal`. |
| `network_monitor.py` | `WAFMonitor`, `ThreatEvent`, `MonitorStats` — inline reverse proxy and passive sniffer with start/stop control. |
| `config.py` | `WAFConfig` dataclass — model path, threshold, proxy/upstream hosts and ports, TLS cert/key, sniffer interface and BPF filter, block/log behavior, logging. |
| `__init__.py` | Package exports: `WAFMonitor`, `WAFEngine`, `WAFConfig`, `ThreatEvent`, `MonitorStats`. |
| `waf_model.pkl` | Trained XGBoost model bundle (model + vectorizer + label encoder + stat feature names). |

## Operating modes

| Mode | HTTP | HTTPS | Can block | Requires |
|------|------|-------|-----------|----------|
| `proxy` (default) | Full inspection | Full inspection (TLS termination) | Yes — returns `403` | TLS cert/key for HTTPS |
| `sniffer` | Full inspection | Metadata only (SNI hostname) | No — log only | `scapy` (+ Npcap on Windows) |

In proxy mode, clean traffic is forwarded to `upstream_host:upstream_port` with an updated `X-Forwarded-For` header. HTTPS interception is enabled only when both `ssl_certfile` and `ssl_keyfile` are set. Sniffer mode can capture `localhost`/`127.0.0.1` traffic by setting `loopback=True`, which requires Npcap installed with loopback support.

## Usage

Network monitor:

```python
from Defensive_Agent import WAFMonitor, WAFConfig

config = WAFConfig(
    model_path="waf_model.pkl",
    proxy_port=8080,
    upstream_host="127.0.0.1",
    upstream_port=80,
    threat_threshold=0.70,
    block_threats=True,
)

monitor = WAFMonitor(config, on_threat=lambda e: print(e.to_dict()))
monitor.start()              # ON  (default = proxy mode)
# monitor.start("sniffer")   # passive capture instead
# ... application runs ...
monitor.stop()               # OFF

print(monitor.stats)         # MonitorStats as a dict
print(monitor.threat_log)    # list of detected ThreatEvent dicts
```

Direct payload analysis (no network layer):

```python
from Defensive_Agent import WAFEngine

engine = WAFEngine("waf_model.pkl")
engine.analyze("' OR 1=1--")
# {'prediction': 'SQLi', 'confidence': 0.99, 'is_threat': True, 'probabilities': {...}}
```

## Configuration

All tunables live on `WAFConfig` (`config.py`). Key fields:

- `model_path` — path to `waf_model.pkl`.
- `threat_threshold` — minimum confidence (0–1) to act on a detection (default `0.70`).
- `proxy_host` / `proxy_port` / `proxy_ssl_port` — proxy bind address and ports.
- `upstream_host` / `upstream_port` / `upstream_ssl` — backend to forward clean traffic to.
- `ssl_certfile` / `ssl_keyfile` — PEM cert/key for HTTPS interception in proxy mode. Generate a self-signed pair with: `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes`.
- `interface` / `loopback` / `sniff_filter` — sniffer-mode interface selection and BPF filter.
- `block_threats` — `True` blocks with `403`; `False` logs and forwards.
- `log_file` / `verbose` — logging destination and level.

## Notes

- The TF-IDF vectorizer and label encoder are embedded in `waf_model.pkl`; loading the model is sufficient — no separate fitting step at runtime.
- Sniffer mode dependencies (`scapy`, and Npcap on Windows) are optional and only imported when that mode is started.

For project-wide setup, Docker, and how the agents report to the dashboard, see the repository root `README.md`.
