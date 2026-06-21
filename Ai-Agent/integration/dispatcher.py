"""
Agent Dispatcher — manages async execution of Offensive and Defensive agents.

Runs scans and monitoring in background threads so the voice loop is never blocked.
Tracks task state and provides status/result queries.
"""

import json
import logging
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from types import SimpleNamespace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from .config import IntegrationConfig
from .contracts import (
    HeartbeatPayload,
    IntentResult,
    OffensiveParams,
    DefensiveStartParams,
)
from .reporting_client import ReportingClient

logger = logging.getLogger("bingo.dispatcher")

_SCAN_RUNNER = Path(__file__).parent.parent / "Offensive-Agent" / "scan_runner.py"


def _register_offensive_pkg():
    import importlib.util

    pkg_name = "offensive_agent_pkg"
    if pkg_name not in sys.modules:
        offensive_dir = Path(__file__).parent.parent / "Offensive-Agent"
        spec = importlib.util.spec_from_file_location(
            pkg_name,
            str(offensive_dir / "__init__.py"),
            submodule_search_locations=[str(offensive_dir)],
        )
        pkg = importlib.util.module_from_spec(spec)
        sys.modules[pkg_name] = pkg
        spec.loader.exec_module(pkg)
    return sys.modules[pkg_name]


def _scan_result_shim(payload: dict):
    """Wrap the runner's compact summary in the attribute shape the GUI expects."""
    confirmed = [
        SimpleNamespace(
            vuln_type=SimpleNamespace(value=v.get("vuln_type", "")),
            severity=SimpleNamespace(value=v.get("severity", "")),
            parameter=v.get("parameter", ""),
            url=v.get("url", ""),
            poc_url=v.get("poc_url", ""),
        )
        for v in payload.get("confirmed", [])
    ]
    summary = payload.get("summary", "")
    return SimpleNamespace(
        target_url=payload.get("target_url", ""),
        confirmed_vulns=confirmed,
        findings=confirmed,
        get_summary=lambda: summary,
    )


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TaskInfo:
    """Tracks state of an async agent task."""
    task_id: str
    task_type: str
    status: TaskStatus = TaskStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Any = None
    error: Optional[str] = None
    params: dict = field(default_factory=dict)
    cancel_event: Any = None
    process: Any = None
    progress_file: Any = None


class AgentDispatcher:
    """
    Dispatches tasks to Offensive and Defensive agents asynchronously.

    Provides:
      - start_offensive_scan(params) → task_id
      - start_defensive_monitor(params)
      - stop_defensive_monitor()
      - get_task_status(task_id) → TaskInfo
      - get_latest_result() → TaskInfo or None
    """

    def __init__(
        self,
        config: IntegrationConfig,
        reporting_client: ReportingClient,
        on_result: Optional[Callable] = None,
        human_callback: Optional[Callable] = None,
    ):
        self._config = config
        self._reporter = reporting_client
        self._on_result = on_result
        self._human_callback = human_callback

        self._executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="bingo-agent")
        self._tasks: dict[str, TaskInfo] = {}
        self._task_counter = 0
        self._lock = threading.Lock()

        self._waf_monitor = None
        self._defensive_running = False

        self._offensive_engine = None

    def _get_offensive_engine(self):
        """Lazy-load the OffensiveEngine (heavy import)."""
        if self._offensive_engine is None:
            pkg = _register_offensive_pkg()
            config_path = self._config.offensive.config_path or None
            self._offensive_engine = pkg.OffensiveEngine(config_path=config_path)
            if self._human_callback:
                self._offensive_engine.set_human_callback(self._human_callback)
            logger.info("Offensive engine initialized")

        return self._offensive_engine

    def start_offensive_scan(self, params: dict) -> str:
        """
        Start an offensive security scan in the background.

        params are validated against OffensiveParams contract before dispatch.

        Returns: task_id string, or "" on validation failure.
        """
        if not self._config.offensive.enabled:
            logger.warning("Offensive agent is disabled in config")
            return ""

        try:
            validated = OffensiveParams(**params)
        except Exception as e:
            logger.error("Offensive params validation failed: %s", e)
            return ""

        if not validated.url:
            logger.error("Cannot start scan: no URL provided")
            return ""

        clean_params = validated.model_dump(exclude_none=True)

        task_id = self._create_task_id("offensive_scan")
        task = TaskInfo(
            task_id=task_id, task_type="offensive_scan", params=clean_params,
            cancel_event=threading.Event(),
        )

        with self._lock:
            self._tasks[task_id] = task

        # Heartbeat is sent from inside _run_offensive_scan (worker thread) so a slow
        # or unreachable reporting endpoint can never block the caller (the voice loop).
        future = self._executor.submit(self._run_offensive_scan, task_id, clean_params)
        future.add_done_callback(lambda f: self._handle_task_done(task_id, f))

        logger.info("Offensive scan started: %s → %s", task_id, validated.url)
        return task_id

    def stop_offensive_scan(self, task_id: str = None) -> list[str]:
        """Signal running offensive scan(s) to stop. They finish their current step
        and report partial findings. Returns the short ids of scans told to stop."""
        with self._lock:
            if task_id and task_id in self._tasks:
                targets = [self._tasks[task_id]]
            else:
                targets = [
                    t for t in self._tasks.values()
                    if t.task_type == "offensive_scan" and t.status == TaskStatus.RUNNING
                ]
        stopped = []
        for t in targets:
            if t.cancel_event is not None:
                t.cancel_event.set()
                stopped.append(self._short_id(t))
                logger.info("Stop requested for %s", t.task_id)
        return stopped

    def _run_offensive_scan(self, task_id: str, params: dict):
        """Run the scan in an isolated process so native crashes can't take down the GUI."""
        with self._lock:
            self._tasks[task_id].status = TaskStatus.RUNNING
            self._tasks[task_id].started_at = datetime.now(timezone.utc)
            cancel_event = self._tasks[task_id].cancel_event

        # Heartbeat runs on this worker thread (not the caller's), so it never
        # blocks the voice loop even if the reporting endpoint is slow or down.
        self._reporter.send_heartbeat(
            agent_name="Bingo Offensive Agent",
            agent_type="offensive",
            status="scanning",
            metadata={"target": params.get("url", "")},
        )

        work_dir = Path(tempfile.mkdtemp(prefix="bingo_scan_"))
        job_file = work_dir / "job.json"
        result_file = work_dir / "result.json"
        cancel_file = work_dir / "cancel.flag"
        progress_file = work_dir / "progress.txt"
        with self._lock:
            self._tasks[task_id].progress_file = str(progress_file)

        job = {
            "params": params,
            "config_path": self._config.offensive.config_path or "",
            "result_file": str(result_file),
            "cancel_file": str(cancel_file),
            "progress_file": str(progress_file),
        }
        job_file.write_text(json.dumps(job), encoding="utf-8")

        proc = subprocess.Popen(
            [sys.executable, str(_SCAN_RUNNER), str(job_file)],
            cwd=str(Path(__file__).parent.parent),
        )
        with self._lock:
            self._tasks[task_id].process = proc

        cancel_sent = False
        while proc.poll() is None:
            if cancel_event.is_set() and not cancel_sent:
                cancel_file.touch()
                cancel_sent = True
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if cancel_sent and proc.poll() is None:
                    try:
                        proc.wait(timeout=60)
                    except subprocess.TimeoutExpired:
                        proc.terminate()
                    break

        payload = None
        if result_file.exists():
            try:
                payload = json.loads(result_file.read_text(encoding="utf-8"))
            except Exception as e:
                logger.error("Could not read scan result file: %s", e)

        try:
            for f in (job_file, result_file, cancel_file, progress_file):
                if f.exists():
                    f.unlink()
            work_dir.rmdir()
        except Exception:
            pass

        if not payload:
            raise RuntimeError(
                "Scan process exited without a result (it may have crashed). "
                "Check logs/offensive_agent.log."
            )
        if not payload.get("ok"):
            raise RuntimeError(payload.get("error", "scan failed"))

        self._reporter.send_heartbeat(
            agent_name="Bingo Offensive Agent",
            agent_type="offensive",
            status="idle",
        )

        return _scan_result_shim(payload)

    def start_defensive_monitor(self, params: dict = None) -> bool:
        """
        Start the WAF network monitor.

        params are validated against DefensiveStartParams contract.

        Returns: True if started successfully
        """
        if not self._config.defensive.enabled:
            logger.warning("Defensive agent is disabled in config")
            return False

        if self._defensive_running:
            logger.warning("Defensive monitor is already running")
            return False

        try:
            validated = DefensiveStartParams(**(params or {}))
        except Exception as e:
            logger.error("Defensive params validation failed: %s", e)
            return False

        try:
            import importlib.util

            defensive_dir = Path(__file__).parent.parent / "Defensive-Agent"
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

            defensive_pkg = sys.modules[pkg_name]
            WAFMonitor = defensive_pkg.WAFMonitor
            WAFConfig = defensive_pkg.WAFConfig

            waf_config = WAFConfig(
                model_path=self._config.defensive.model_path,
                threat_threshold=self._config.defensive.threat_threshold,
                proxy_port=self._config.defensive.proxy_port,
                upstream_host=validated.upstream_host or self._config.defensive.upstream_host,
                upstream_port=validated.upstream_port or self._config.defensive.upstream_port,
                block_threats=self._config.defensive.block_threats,
                loopback=validated.loopback,
            )

            if validated.port and f"tcp port {validated.port}" not in waf_config.sniff_filter:
                waf_config.sniff_filter += f" or tcp port {validated.port}"

            self._waf_monitor = WAFMonitor(
                config=waf_config,
                on_threat=self._on_threat_detected,
            )

            self._waf_monitor.start(mode=validated.mode)
            self._defensive_running = True

            self._reporter.send_heartbeat(
                agent_name="Bingo Defensive Agent",
                agent_type="defensive",
                status="monitoring",
                metadata={"mode": validated.mode, "port": waf_config.proxy_port, "loopback": validated.loopback},
            )

            logger.info("Defensive monitor started (%s mode)", validated.mode)
            return True

        except Exception as e:
            logger.error("Failed to start defensive monitor: %s", e)
            return False

    def stop_defensive_monitor(self) -> bool:
        """Stop the WAF network monitor."""
        if not self._defensive_running or self._waf_monitor is None:
            logger.warning("Defensive monitor is not running")
            return False

        try:
            self._waf_monitor.stop()
            self._defensive_running = False

            self._reporter.send_heartbeat(
                agent_name="Bingo Defensive Agent",
                agent_type="defensive",
                status="idle",
            )

            logger.info("Defensive monitor stopped")
            return True
        except Exception as e:
            logger.error("Failed to stop defensive monitor: %s", e)
            return False

    def get_defensive_status(self) -> dict:
        """Get current defensive monitor status and stats."""
        if not self._defensive_running or self._waf_monitor is None:
            return {
                "running": False,
                "message": "WAF monitor is not running.",
            }

        stats = self._waf_monitor.stats
        recent_threats = self._waf_monitor.threat_log[-5:]

        return {
            "running": True,
            "stats": stats,
            "recent_threats": recent_threats,
            "message": (
                f"WAF is active. "
                f"Total requests: {stats.get('total_requests', 0)}. "
                f"Threats detected: {stats.get('threats_detected', 0)}. "
                f"Threats blocked: {stats.get('threats_blocked', 0)}."
            ),
        }

    def _on_threat_detected(self, threat_event):
        """Callback when the WAF detects a threat — reports to website."""
        try:
            self._reporter.submit_threat_incident(threat_event)
        except Exception as e:
            logger.error("Failed to report threat incident: %s", e)

        if self._on_result:
            task = TaskInfo(
                task_id=f"threat_{int(time.time())}",
                task_type="defensive_threat",
                status=TaskStatus.COMPLETED,
                completed_at=datetime.now(timezone.utc),
                result=threat_event,
            )
            try:
                self._on_result(task)
            except Exception as e:
                logger.error("Result callback failed: %s", e)

    def get_task_status(self, task_id: str) -> Optional[TaskInfo]:
        """Get status of a specific task."""
        with self._lock:
            return self._tasks.get(task_id)

    def get_latest_scan_result(self) -> Optional[TaskInfo]:
        """Get the most recent offensive scan task."""
        with self._lock:
            scan_tasks = [
                t for t in self._tasks.values()
                if t.task_type == "offensive_scan"
            ]
            if not scan_tasks:
                return None
            return max(scan_tasks, key=lambda t: t.started_at or datetime.min.replace(tzinfo=timezone.utc))

    def get_active_scans(self) -> list[TaskInfo]:
        """Get all currently running scans."""
        with self._lock:
            return [
                t for t in self._tasks.values()
                if t.status == TaskStatus.RUNNING
            ]

    AVG_SCAN_SECONDS = 180
    MAX_SCAN_SECONDS = 900

    @staticmethod
    def _short_id(task: TaskInfo) -> str:
        parts = task.task_id.split("_")
        return f"scan #{parts[2]}" if len(parts) >= 3 and parts[2].isdigit() else task.task_id

    def _elapsed(self, task: TaskInfo) -> int:
        if not task.started_at:
            return 0
        return int((datetime.now(timezone.utc) - task.started_at).total_seconds())

    @staticmethod
    def _read_current_step(task: TaskInfo) -> str:
        path = task.progress_file
        if not path:
            return ""
        try:
            import os as _os
            if not _os.path.exists(path):
                return ""
            with open(path, encoding="utf-8") as f:
                raw = f.read().strip()
            return raw.split("\t", 1)[-1] if raw else ""
        except Exception:
            return ""

    def get_scan_progress(self) -> dict:
        """Elapsed time, ETA, identifier, current step and stuck-flag for the running scan."""
        active = self.get_active_scans()
        if active:
            task = max(active, key=lambda t: t.started_at or datetime.now(timezone.utc))
            elapsed = self._elapsed(task)
            avg = self._completed_avg() or self.AVG_SCAN_SECONDS
            stuck = elapsed > max(int(avg * 2.5), 420) or elapsed > self.MAX_SCAN_SECONDS
            return {
                "running": True,
                "id": self._short_id(task),
                "count": len(active),
                "target": task.params.get("url", "?"),
                "elapsed": elapsed,
                "eta": max(0, avg - elapsed),
                "avg": avg,
                "stuck": stuck,
                "current_step": self._read_current_step(task),
            }
        latest = self.get_latest_scan_result()
        if latest and latest.started_at and latest.completed_at:
            return {
                "running": False,
                "id": self._short_id(latest),
                "last_duration": int((latest.completed_at - latest.started_at).total_seconds()),
            }
        return {"running": False}

    def get_scans_summary(self) -> list[dict]:
        """One line per offensive scan so the user can tell them apart by id."""
        with self._lock:
            tasks = [t for t in self._tasks.values() if t.task_type == "offensive_scan"]
        out = []
        for t in sorted(tasks, key=lambda x: x.started_at or datetime.min.replace(tzinfo=timezone.utc), reverse=True):
            elapsed = self._elapsed(t)
            avg = self._completed_avg() or self.AVG_SCAN_SECONDS
            out.append({
                "id": self._short_id(t),
                "target": t.params.get("url", "?"),
                "status": t.status.value,
                "elapsed": elapsed,
                "stuck": t.status == TaskStatus.RUNNING and (elapsed > max(int(avg * 2.5), 420) or elapsed > self.MAX_SCAN_SECONDS),
            })
        return out

    def _completed_avg(self) -> int:
        with self._lock:
            durs = [
                (t.completed_at - t.started_at).total_seconds()
                for t in self._tasks.values()
                if t.task_type == "offensive_scan" and t.started_at and t.completed_at
            ]
        return int(sum(durs) / len(durs)) if durs else 0

    def _create_task_id(self, prefix: str) -> str:
        with self._lock:
            self._task_counter += 1
            return f"{prefix}_{self._task_counter}_{int(time.time())}"

    def _handle_task_done(self, task_id: str, future: Future):
        """Called when a background task completes or fails."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return

        try:
            result = future.result()
            with self._lock:
                task.status = TaskStatus.COMPLETED
                task.completed_at = datetime.now(timezone.utc)
                task.result = result
            logger.info("Task completed: %s", task_id)
        except Exception as e:
            with self._lock:
                task.status = TaskStatus.FAILED
                task.completed_at = datetime.now(timezone.utc)
                task.error = str(e)
            logger.error("Task failed: %s — %s", task_id, e)

        if self._on_result:
            try:
                self._on_result(task)
            except Exception as e:
                logger.error("Result callback failed: %s", e)

    def shutdown(self):
        """Clean shutdown of all agents and thread pool."""
        if self._defensive_running:
            self.stop_defensive_monitor()
        self._executor.shutdown(wait=False)
        logger.info("Dispatcher shut down")
