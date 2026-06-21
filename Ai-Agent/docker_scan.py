"""Containerised end-to-end DVWA scan runner.

Bootstraps a DVWA target (create DB -> login -> security=low), grabs a valid
session, then runs the Offensive engine against it. Designed to run inside the
`bingo-agent` Docker image on the same network as the `dvwa` container.

Env vars:
  TARGET            target base URL            (default: http://dvwa)
  DVWA_USER         login username             (default: admin)
  DVWA_PASS         login password             (default: password)
  DVWA_SECURITY     security level             (default: low)
  SCAN_VULN_TYPES   comma list to restrict     (default: all auto-detected)
  OPENAI_API_KEY    required
"""
import importlib.util
import os
import re
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

AI_DIR = Path(__file__).parent
sys.path.insert(0, str(AI_DIR))
os.chdir(AI_DIR)
load_dotenv()

TARGET = os.getenv("TARGET", "http://dvwa").rstrip("/")
USER = os.getenv("DVWA_USER", "admin")
PASS = os.getenv("DVWA_PASS", "password")
SECURITY = os.getenv("DVWA_SECURITY", "low")
_TOKEN_RE = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]")

def _token(session: requests.Session, url: str) -> str:
    m = _TOKEN_RE.search(session.get(url, timeout=15).text)
    return m.group(1) if m else ""

def bootstrap_dvwa() -> dict:
    """Create DB, log in, set security level. Returns cookie dict for the scan."""
    s = requests.Session()
    try:
        tok = _token(s, f"{TARGET}/setup.php")
        s.post(
            f"{TARGET}/setup.php",
            data={"create_db": "Create / Reset Database", "user_token": tok},
            timeout=30,
        )
    except Exception as e:
        print(f"[!] DVWA setup step failed (continuing): {e}")

    tok = _token(s, f"{TARGET}/login.php")
    s.post(
        f"{TARGET}/login.php",
        data={"username": USER, "password": PASS, "Login": "Login", "user_token": tok},
        timeout=30,
        allow_redirects=True,
    )

    tok = _token(s, f"{TARGET}/security.php")
    s.post(
        f"{TARGET}/security.php",
        data={"security": SECURITY, "seclvl_submit": "Submit", "user_token": tok},
        timeout=15,
    )

    cookies = s.cookies.get_dict()
    cookies.setdefault("security", SECURITY)
    idx = s.get(f"{TARGET}/index.php", timeout=15, allow_redirects=False)
    print(f"[*] DVWA bootstrap: cookies={list(cookies)} index_status={idx.status_code}")
    return cookies

def load_engine():
    offensive_dir = AI_DIR / "Offensive-Agent"
    pkg = "offensive_agent_pkg"
    if pkg not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            pkg,
            str(offensive_dir / "__init__.py"),
            submodule_search_locations=[str(offensive_dir)],
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[pkg] = module
        spec.loader.exec_module(module)
    return sys.modules[pkg].OffensiveEngine

def main():
    if not os.getenv("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY is not set")

    cookies = bootstrap_dvwa()
    OffensiveEngine = load_engine()
    engine = OffensiveEngine()

    print("[*] Ingesting knowledge base...")
    try:
        print(f"[+] Ingested {engine.ingest_knowledge_base()} chunks")
    except Exception as e:
        print(f"[!] KB ingestion: {e}")

    vt = os.getenv("SCAN_VULN_TYPES")
    vuln_types = [v.strip() for v in vt.split(",")] if vt else None

    print(f"\n[*] Scanning {TARGET} (security={SECURITY})...")
    result = engine.scan(
        url=TARGET, username=USER, password=PASS, cookies=cookies, vuln_types=vuln_types
    )

    print(f"\n{'=' * 64}\nSCAN COMPLETE: {result.get_summary()}")
    print(f"Duration: {result.duration_seconds:.0f}s\n{'=' * 64}")
    for f in result.findings:
        conf = getattr(f.confidence, "value", f.confidence)
        sev = getattr(f.severity, "value", f.severity)
        vtv = getattr(f.vuln_type, "value", f.vuln_type)
        print(f"  [{sev.upper():8}] {vtv:18} {conf:11} @ {f.url} param={f.parameter}")
        if f.payload:
            print(f"             payload: {f.payload[:100]}")
    if not result.findings:
        print("  No findings!")
    if result.errors:
        print(f"\n[!] Errors ({len(result.errors)}):")
        for e in result.errors:
            print(f"  - {e}")

if __name__ == "__main__":
    main()
