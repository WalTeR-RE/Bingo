"""Run the defensive WAF proxy in front of a (locally hosted) target and keep
it alive. Threats are blocked (403) and reported to the dashboard as incidents.

Env:
  WAF_UPSTREAM_HOST  upstream to protect (default: dvwa)
  WAF_UPSTREAM_PORT  upstream port       (default: 80)
  WAF_PROXY_PORT     listen port         (default: from integration config = 8080)
  BINGO_API_URL / BINGO_ACCESS_TOKEN  for incident reporting (optional)
"""
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent))
load_dotenv(Path(__file__).parent / ".env")

from integration.config import load_integration_config
from integration.dispatcher import AgentDispatcher
from integration.reporting_client import ReportingClient

cfg = load_integration_config()
disp = AgentDispatcher(cfg, ReportingClient(cfg))

up_host = os.getenv("WAF_UPSTREAM_HOST", "dvwa")
up_port = int(os.getenv("WAF_UPSTREAM_PORT", "80"))

ok = disp.start_defensive_monitor(
    {"mode": "proxy", "upstream_host": up_host, "upstream_port": up_port}
)
if not ok:
    sys.exit("WAF failed to start")

print(
    f"[WAF] LIVE on 0.0.0.0:{cfg.defensive.proxy_port}  ->  {up_host}:{up_port}  "
    f"(block_threats={cfg.defensive.block_threats})",
    flush=True,
)
print("[WAF] Route traffic through the proxy port; Ctrl+C to stop.", flush=True)
try:
    while True:
        time.sleep(10)
        s = disp.get_defensive_status().get("stats", {})
        print(
            f"[WAF] total={s.get('total_requests', 0)} safe={s.get('safe_requests', 0)} "
            f"threats={s.get('threats_detected', 0)} blocked={s.get('threats_blocked', 0)}",
            flush=True,
        )
except KeyboardInterrupt:
    disp.stop_defensive_monitor()
    print("[WAF] stopped.")
