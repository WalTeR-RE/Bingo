"""
Offensive AI Agent — Test Script
=================================
Run this to test the full pipeline against a target.

Usage:
    cd d:\\Study\\Graduation\\offensive\\autodvwa-exploit
    python -m final_result.test

Or:
    python final_result/test.py
"""

import sys
from pathlib import Path

# Ensure parent dir is on path so `final_result` is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from final_result.api import OffensiveEngine


def main():
    engine = OffensiveEngine()

    print("[*] Ingesting knowledge base...")
    count = engine.ingest_knowledge_base()
    print(f"[+] Ingested {count} chunks into vector store")

    print("\n[*] Starting full scan...")
    result = engine.scan(
        url="http://127.0.0.1:4280/vulnerabilities/sqli/",
        username="admin",
        password="password",
        cookies={"PHPSESSID": "your_session_id", "security": "low"},
    )
    print(f"\n[+] {result.get_summary()}")
    for finding in result.findings:
        print(
            f"  - [{finding.severity.value.upper()}] {finding.vuln_type.value} "
            f"on {finding.parameter} (confidence: {finding.confidence.value})"
        )
    if result.errors:
        print(f"\n[!] Errors: {result.errors}")

    print("\n[*] Starting targeted XSS scan...")
    result2 = engine.scan(
        url="http://127.0.0.1:4280/vulnerabilities/xss_r/",
        username="admin",
        password="password",
        cookies={"PHPSESSID": "your_session_id", "security": "low"},
        vuln_types=["xss"],
    )
    print(f"[+] {result2.get_summary()}")

    # ─── Example 3: Integration-style call (how BINGO would call it) ───
    # from final_result import OffensiveEngine
    # engine = OffensiveEngine(config_path="/path/to/custom/config.yaml")
    # result = engine.scan(url=url_from_user, username=u, password=p)
    # return result.model_dump()  # JSON-serializable dict for BINGO


if __name__ == "__main__":
    main()
