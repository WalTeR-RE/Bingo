"""Quick full-DVWA scan test."""
import sys, os, importlib.util
from pathlib import Path

ai_dir = Path(__file__).parent
sys.path.insert(0, str(ai_dir))
os.chdir(ai_dir)

from dotenv import load_dotenv
load_dotenv()

# Import Offensive-Agent (hyphenated dir) via importlib
offensive_dir = ai_dir / "Offensive-Agent"
pkg_name = "offensive_agent_pkg"
if pkg_name not in sys.modules:
    spec = importlib.util.spec_from_file_location(
        pkg_name,
        str(offensive_dir / "__init__.py"),
        submodule_search_locations=[str(offensive_dir)],
    )
    pkg = importlib.util.module_from_spec(spec)
    sys.modules[pkg_name] = pkg
    spec.loader.exec_module(pkg)

OffensiveEngine = sys.modules[pkg_name].OffensiveEngine

def main():
    engine = OffensiveEngine()

    print("[*] Ingesting knowledge base...")
    try:
        count = engine.ingest_knowledge_base()
        print(f"[+] Ingested {count} chunks")
    except Exception as e:
        print(f"[!] KB ingestion: {e}")

    print("\n[*] Starting full DVWA scan (security=low)...")
    result = engine.scan(
        url="http://localhost:4280",
        username="admin",
        password="password",
        cookies={"security": "low"},
    )

    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE: {result.get_summary()}")
    print(f"Duration: {result.duration_seconds:.0f}s")
    print(f"{'='*60}")

    if result.findings:
        for f in result.findings:
            status = f.confidence.value.upper() if hasattr(f.confidence, 'value') else str(f.confidence)
            sev = f.severity.value.upper() if hasattr(f.severity, 'value') else str(f.severity)
            vt = f.vuln_type.value if hasattr(f.vuln_type, 'value') else str(f.vuln_type)
            print(f"  [{sev}] {vt} @ {f.url} param={f.parameter} ({status})")
            if f.payload:
                print(f"         payload: {f.payload[:100]}")
    else:
        print("  No findings!")

    if result.errors:
        print(f"\n[!] Errors ({len(result.errors)}):")
        for e in result.errors:
            print(f"  - {e}")

if __name__ == "__main__":
    main()
