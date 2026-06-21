import json
import sys
import os
from pathlib import Path


class _FileCancel:
    def __init__(self, path):
        self._path = path

    def is_set(self):
        return bool(self._path) and os.path.exists(self._path)

    def set(self):
        try:
            Path(self._path).touch()
        except Exception:
            pass


def _register_pkg():
    import importlib.util

    pkg_name = "offensive_agent_pkg"
    if pkg_name not in sys.modules:
        offensive_dir = Path(__file__).parent
        spec = importlib.util.spec_from_file_location(
            pkg_name,
            str(offensive_dir / "__init__.py"),
            submodule_search_locations=[str(offensive_dir)],
        )
        pkg = importlib.util.module_from_spec(spec)
        sys.modules[pkg_name] = pkg
        spec.loader.exec_module(pkg)
    return sys.modules[pkg_name]


def _summarize(result):
    confirmed = []
    for v in result.confirmed_vulns:
        confirmed.append({
            "vuln_type": getattr(v.vuln_type, "value", str(v.vuln_type)),
            "severity": getattr(v.severity, "value", str(v.severity)),
            "parameter": v.parameter or "",
            "url": v.url or "",
            "poc_url": v.poc_url or "",
        })
    return {
        "ok": True,
        "target_url": result.target_url,
        "summary": result.get_summary(),
        "confirmed": confirmed,
    }


def main():
    with open(sys.argv[1], encoding="utf-8") as f:
        job = json.load(f)

    try:
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
    except Exception:
        pass

    params = job["params"]
    result_path = job["result_file"]
    cancel_event = _FileCancel(job.get("cancel_file", ""))
    if job.get("progress_file"):
        os.environ["BINGO_PROGRESS_FILE"] = job["progress_file"]

    try:
        pkg = _register_pkg()
        from offensive_agent_pkg.utils.progress import set_progress
        set_progress("initializing scan engine")
        engine = pkg.OffensiveEngine(config_path=job.get("config_path") or None)
        result = engine.scan(
            url=params["url"],
            username=params.get("username", ""),
            password=params.get("password", ""),
            cookies=params.get("cookies"),
            vuln_types=params.get("vuln_types"),
            scan_level=params.get("scan_level", 2),
            cancel_event=cancel_event,
        )
        payload = _summarize(result)
    except Exception as exc:
        import traceback
        payload = {"ok": False, "error": str(exc), "trace": traceback.format_exc()}

    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, default=str)


if __name__ == "__main__":
    main()
