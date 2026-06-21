"""
Bingo Integration Test — validates the full system without voice I/O.

This script tests:
  1. Configuration loading
  2. Intent routing (classifies sample phrases)
  3. Reporting client connectivity (heartbeat + mock report)
  4. Dispatcher task lifecycle

Run from the Ai-Agent/ directory:
    python integration_test.py

Requirements:
    - OPENAI_API_KEY set in environment
    - BINGO_ACCESS_TOKEN set in environment (or in integration_config.yaml)
    - Website backend running at http://localhost:8000
"""

import os
import sys
import time
from pathlib import Path

# Ensure Ai-Agent is on path
sys.path.insert(0, str(Path(__file__).parent))

from openai import OpenAI


def test_config():
    """Test 1: Configuration loading."""
    print("\n" + "=" * 60)
    print("TEST 1: Configuration Loading")
    print("=" * 60)

    from integration.config import load_integration_config

    config = load_integration_config()
    print(f"  Website URL:       {config.website.base_url}")
    print(f"  Access Token:      {'SET' if config.website.access_token else 'NOT SET'}")
    print(f"  Offensive config:  {config.offensive.config_path}")
    print(f"  Offensive enabled: {config.offensive.enabled}")
    print(f"  Defensive model:   {config.defensive.model_path}")
    print(f"  Defensive enabled: {config.defensive.enabled}")

    assert config.website.base_url, "Website base_url is empty"
    print("  [PASS] Config loaded successfully")
    return config


def test_intent_router():
    """Test 2: Intent classification."""
    print("\n" + "=" * 60)
    print("TEST 2: Intent Router")
    print("=" * 60)

    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    from integration.intent_router import IntentRouter

    router = IntentRouter(client, model="gpt-4o-mini")

    test_cases = [
        ("scan example.com for SQL injection", "offensive"),
        ("run a pentest on 192.168.1.1", "offensive"),
        ("start monitoring the network", "defensive_start"),
        ("stop the WAF", "defensive_stop"),
        ("how many threats did you detect?", "defensive_status"),
        ("is the scan done yet?", "scan_status"),
        ("what is cross-site scripting?", "conversation"),
        ("hello bingo", "conversation"),
    ]

    passed = 0
    for text, expected in test_cases:
        result = router.classify(text)
        actual = result["intent"]
        status = "PASS" if actual == expected else "FAIL"
        if status == "PASS":
            passed += 1
        print(f"  [{status}] \"{text}\" → {actual} (expected: {expected})")
        if result.get("params"):
            print(f"         params: {result['params']}")

    print(f"\n  Results: {passed}/{len(test_cases)} passed")
    return passed == len(test_cases)


def test_reporting_client(config):
    """Test 3: Reporting client — heartbeat + report."""
    print("\n" + "=" * 60)
    print("TEST 3: Reporting Client")
    print("=" * 60)

    from integration.reporting_client import ReportingClient

    reporter = ReportingClient(config)

    if not reporter.is_configured:
        print("  [SKIP] Reporter not configured (no access token)")
        return False

    print("  Sending heartbeat...")
    ok = reporter.send_heartbeat(
        agent_name="Integration Test",
        agent_type="offensive",
        status="idle",
        metadata={"test": True},
    )
    print(f"  [{'PASS' if ok else 'FAIL'}] Heartbeat: {'sent' if ok else 'failed'}")

    return ok


def test_dispatcher_lifecycle(config):
    """Test 4: Dispatcher task management (no actual scan)."""
    print("\n" + "=" * 60)
    print("TEST 4: Dispatcher Lifecycle")
    print("=" * 60)

    from integration.reporting_client import ReportingClient
    from integration.dispatcher import AgentDispatcher, TaskStatus

    reporter = ReportingClient(config)
    results_received = []

    def on_result(task):
        results_received.append(task)

    dispatcher = AgentDispatcher(
        config=config,
        reporting_client=reporter,
        on_result=on_result,
    )

    status = dispatcher.get_defensive_status()
    assert not status["running"], "Should not be running initially"
    print(f"  [PASS] Defensive status: {status['message']}")

    latest = dispatcher.get_latest_scan_result()
    assert latest is None, "Should have no scan results"
    print("  [PASS] No scan results initially")

    active = dispatcher.get_active_scans()
    assert len(active) == 0, "Should have no active scans"
    print("  [PASS] No active scans initially")

    task_id = dispatcher.start_offensive_scan({})
    assert task_id == "", "Should reject scan without URL"
    print("  [PASS] Rejected scan with no URL")

    dispatcher.shutdown()
    print("  [PASS] Dispatcher shutdown cleanly")
    return True


def test_defensive_waf_engine():
    """Test 5: WAF engine payload analysis (if model exists)."""
    print("\n" + "=" * 60)
    print("TEST 5: WAF Engine (Defensive)")
    print("=" * 60)

    from integration.config import load_integration_config
    config = load_integration_config()

    model_path = config.defensive.model_path
    if not model_path or not Path(model_path).exists():
        print(f"  [SKIP] WAF model not found at: {model_path}")
        return False

    # Import using importlib (directory has a hyphen)
    import importlib.util

    defensive_dir = Path(__file__).parent / "Defensive-Agent"
    pkg_name = "defensive_agent_pkg"

    if pkg_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            pkg_name,
            str(defensive_dir / "__init__.py"),
            submodule_search_locations=[str(defensive_dir)],
        )
        pkg = importlib.util.module_from_spec(spec)
        sys.modules[pkg_name] = pkg
        spec.loader.exec_module(pkg)

    WAFEngine = sys.modules[pkg_name].WAFEngine

    engine = WAFEngine(model_path)

    test_payloads = [
        ("?q=shoes&page=2", False, "Benign"),
        ("?id=1' OR '1'='1'--", True, "SQLi"),
        ("<script>alert(1)</script>", True, "XSS"),
        ("../../etc/passwd", True, "LFI"),
    ]

    passed = 0
    for payload, expect_threat, expect_type in test_payloads:
        result = engine.analyze(payload)
        is_ok = result["is_threat"] == expect_threat
        if is_ok:
            passed += 1
        print(
            f"  [{'PASS' if is_ok else 'FAIL'}] "
            f"\"{payload[:40]}\" → {result['prediction']} "
            f"({result['confidence']:.2%}) threat={result['is_threat']}"
        )

    print(f"\n  Results: {passed}/{len(test_payloads)} passed")
    return passed == len(test_payloads)


def main():
    print("=" * 60)
    print("BINGO INTEGRATION TEST SUITE")
    print("=" * 60)

    results = {}

    try:
        config = test_config()
        results["config"] = True
    except Exception as e:
        print(f"  [FAIL] {e}")
        results["config"] = False
        config = None

    if os.environ.get("OPENAI_API_KEY"):
        try:
            results["intent_router"] = test_intent_router()
        except Exception as e:
            print(f"  [FAIL] {e}")
            results["intent_router"] = False
    else:
        print("\n  [SKIP] Intent router (OPENAI_API_KEY not set)")
        results["intent_router"] = None

    if config:
        try:
            results["reporting"] = test_reporting_client(config)
        except Exception as e:
            print(f"  [FAIL] {e}")
            results["reporting"] = False
    else:
        results["reporting"] = None

    if config:
        try:
            results["dispatcher"] = test_dispatcher_lifecycle(config)
        except Exception as e:
            print(f"  [FAIL] {e}")
            results["dispatcher"] = False
    else:
        results["dispatcher"] = None

    try:
        results["waf_engine"] = test_defensive_waf_engine()
    except Exception as e:
        print(f"  [FAIL] {e}")
        results["waf_engine"] = False

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for name, status in results.items():
        icon = "PASS" if status is True else ("SKIP" if status is None else "FAIL")
        print(f"  [{icon}] {name}")

    all_passed = all(v is True for v in results.values() if v is not None)
    print(f"\nOverall: {'ALL PASSED' if all_passed else 'SOME FAILED'}")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
