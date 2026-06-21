import os
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, quote, urljoin, urlparse

import requests

from ..agents.base_exploit import BaseExploitAgent
from ..agents.configs import EXPLOIT_CONFIGS
from ..agents.discovery import DiscoveryAgent
from ..agents.planner import PlannerAgent
from ..agents.recon import ReconAgent
from ..agents.router import RouterAgent
from ..core.active_discovery import ActiveDiscovery
from ..core.config import AppConfig
from ..core.profiles import detect_profile
from ..core.surface import map_attack_surface, normalize_url
from ..core.types import Confidence, Severity, VulnType
from ..models.schemas import (
    AttackPlan,
    Credentials,
    ScanRequest,
    ScanResult,
    VulnerabilityFinding,
)
from ..utils.logger import console_print, get_logger
from ..utils.memory import SharedMemory
from ..utils.rag import RAGEngine
from ..utils.progress import set_progress
from ..utils.reporter import Reporter
from ..utils.validator import Validator
from ..web_analyzer.analyzer import WebAnalyzer

logger = get_logger("orchestrator")

_POC_SAFE = "<>=;:()[]{}/|,.!*@^~$-"

_ARTIFACT_PROTECTED_SUFFIXES = {
    ".py", ".pyc", ".pyo", ".pkl", ".md", ".yaml", ".yml", ".ini",
    ".cfg", ".toml", ".json", ".log", ".lock", ".env",
}
_ARTIFACT_PROTECTED_NAMES = {".gitignore", ".env", "requirements.txt", "requirements-gui.txt"}


def _snapshot_artifacts():
    """Record the top-level files in the scan working directory so any files the
    scan creates (webshells, cookie jars, downloaded payloads, tool output) can
    be identified and removed afterward. Returns None to disable cleanup, either
    on error or when BINGO_KEEP_ARTIFACTS=1 is set (keep artifacts for debugging)."""
    if os.environ.get("BINGO_KEEP_ARTIFACTS") == "1":
        return None
    try:
        return {e for e in os.listdir(".") if os.path.isfile(e)}
    except Exception:
        return None


def _cleanup_scan_artifacts(before):
    """Delete files that appeared in the working directory during the scan,
    leaving everything that existed beforehand plus source, config, reports and
    logs (by extension) untouched. No-op if snapshotting was disabled."""
    if before is None:
        return
    try:
        current = {e for e in os.listdir(".") if os.path.isfile(e)}
    except Exception:
        return
    removed = []
    for name in current - before:
        if name in _ARTIFACT_PROTECTED_NAMES:
            continue
        if os.path.splitext(name)[1].lower() in _ARTIFACT_PROTECTED_SUFFIXES:
            continue
        try:
            os.remove(name)
            removed.append(name)
        except Exception as e:
            logger.warning("Could not remove scan artifact %s: %s", name, e)
    if removed:
        logger.info("Cleaned up %d scan artifact(s): %s", len(removed), ", ".join(sorted(removed)))


class Orchestrator:
    """Core pipeline: recon → discovery → route → plan → exploit → validate → report."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.rag_engine = RAGEngine(config)
        self.validator = Validator()
        self.reporter = Reporter(config)
        self.human_callback = None

    _LEVELS = {
        1: {"max_pages": 12, "iter_mult": 0.6, "retry_rounds": 0, "max_parallel": 4},
        2: {"max_pages": 25, "iter_mult": 1.0, "retry_rounds": 2, "max_parallel": None},
        3: {"max_pages": 60, "iter_mult": 1.8, "retry_rounds": 5, "max_parallel": None},
    }

    def _level_params(self, level) -> dict:
        try:
            return self._LEVELS.get(int(level), self._LEVELS[2])
        except (TypeError, ValueError):
            return self._LEVELS[2]

    @staticmethod
    def _stop(cancel_event) -> bool:
        return bool(cancel_event is not None and cancel_event.is_set())

    def scan(self, request: ScanRequest, cancel_event=None) -> ScanResult:
        """Run the offensive scan, then delete any files it created in the working
        directory (webshells, cookie jars, downloaded payloads, tool output) so
        nothing is left behind. Set BINGO_KEEP_ARTIFACTS=1 to keep them."""
        before = _snapshot_artifacts()
        try:
            return self._run_pipeline(request, cancel_event)
        finally:
            _cleanup_scan_artifacts(before)

    def _run_pipeline(self, request: ScanRequest, cancel_event=None) -> ScanResult:
        """Run the full offensive security scan pipeline."""
        scan_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        memory = SharedMemory()
        lp = self._level_params(request.scan_level)

        logger.info(f"[{scan_id}] Starting scan of {request.url} (level {request.scan_level})")
        result = ScanResult(target_url=request.url, scan_id=scan_id)

        try:
            auth_cookies = self._authenticate(request)
        except Exception as e:
            logger.warning(f"[{scan_id}] Auth step failed: {e}")
            auth_cookies = {}
        if auth_cookies:
            if request.credentials is None:
                request.credentials = Credentials(cookies=auth_cookies)
            else:
                merged = dict(request.credentials.cookies or {})
                merged.update(auth_cookies)
                request.credentials.cookies = merged
            logger.info(f"[{scan_id}] Authenticated session: cookies={list(auth_cookies)}")
        if request.credentials:
            memory.set_credentials(request.credentials)

        findings: list[VulnerabilityFinding] = []
        inventory: list = []
        profile = None
        cancelled = False
        try:
            logger.info(f"[{scan_id}] Phase 0: Reconnaissance")
            set_progress("reconnaissance & crawling the site")
            recon_output, web_output = self._run_recon_parallel(request, memory, lp["max_pages"])
            result.recon_summary = recon_output
            result.web_analysis = web_output

            if self._stop(cancel_event):
                cancelled = True
            else:
                logger.info(f"[{scan_id}] Phase 1: Vulnerability Discovery")
                set_progress("discovering vulnerabilities (attack surface analysis)")
                discovery_agent = DiscoveryAgent(self.config, self.rag_engine)
                discovery_output = discovery_agent.run(
                    url=request.url,
                    recon_data=recon_output.model_dump_json() if recon_output else "{}",
                    web_analysis=web_output.model_dump_json() if web_output else "{}",
                )
                self._enrich_discovery_urls(discovery_output, web_output, request.url)
                inventory, profile = self._expand_surface(
                    request, discovery_output, web_output, recon_output, lp, cancel_event
                )
                result.discovery = discovery_output
                memory.set_discovery(discovery_output)

                logger.info(f"[{scan_id}] Phase 2: Vulnerability Routing")
                router = RouterAgent(self.config)
                route_output = router.run(discovery_output.model_dump_json())
                vuln_types = list(route_output.vuln_types)
                for f in discovery_output.potential_vulns:
                    if f.vuln_type and f.vuln_type not in vuln_types:
                        vuln_types.append(f.vuln_type)
                if request.vuln_types:
                    allowed = {v.value for v in request.vuln_types}
                    vuln_types = [v for v in vuln_types if v in allowed]

                if self._stop(cancel_event):
                    cancelled = True
                elif vuln_types:
                    logger.info(f"[{scan_id}] Testing: {vuln_types}")
                    logger.info(f"[{scan_id}] Phase 3-4: Planning & Exploitation")
                    findings = self._exploit_parallel(
                        request, vuln_types, discovery_output, memory, lp, cancel_event,
                        inventory=inventory, profile=profile,
                    )
                else:
                    logger.info(f"[{scan_id}] No vulnerabilities to test")
        except Exception as e:
            logger.error(f"[{scan_id}] Scan failed: {e}")
            memory.add_error(str(e))

        if self._stop(cancel_event):
            cancelled = True

        logger.info(f"[{scan_id}] Phase 5: Validation")
        set_progress("validating findings")
        result.findings = self.validator.validate_all(findings)
        logger.info(f"[{scan_id}] Phase 6: Reporting")
        set_progress("writing report")
        result.duration_seconds = time.time() - start_time
        result.errors = memory.get_errors()
        if cancelled:
            result.errors.append("Scan was stopped early by the user — these are partial results.")

        try:
            self.reporter.save_local(result)
            self.reporter.report(result)
        except Exception as e:
            logger.error(f"[{scan_id}] Reporting failed: {e}")

        logger.info(f"[{scan_id}] Scan {'STOPPED' if cancelled else 'complete'}: {result.get_summary()}")
        return result

    _PATH_HINTS = {
        "sqli": ["sqli"],
        "xss": ["xss"],
        "lfi": ["fi", "inclusion", "file"],
        "rfi": ["fi", "inclusion"],
        "command_injection": ["exec", "command"],
        "csrf": ["csrf"],
        "file_upload": ["upload"],
        "brute_force": ["brute", "login"],
        "open_redirect": ["redirect"],
        "idor": ["idor", "weak"],
    }

    def _enrich_discovery_urls(self, discovery_output, web_analysis, base_url):
        """Fill in / correct each finding's `location` using crawled forms+links.

        The discovery LLM reliably names the vulnerable *parameter* but often
        leaves the endpoint URL blank. We build a parameter -> [(url, method)]
        index from the real attack surface and map each finding back to a
        concrete endpoint, preferring URLs whose path matches the vuln type.
        """
        if not web_analysis or not discovery_output.potential_vulns:
            return

        param_targets: dict[str, list[tuple[str, str]]] = {}

        def _add(param: str, url: str, method: str):
            key = (param or "").strip().lower()
            if not key or not url:
                return
            bucket = param_targets.setdefault(key, [])
            if (url, method) not in bucket:
                bucket.append((url, method))

        for form in web_analysis.forms:
            url = form.action or form.page_url
            method = (form.method or "GET").upper()
            for inp in form.inputs:
                _add(inp.get("name", ""), url, method)
        for link in web_analysis.links:
            query = urlparse(link).query
            for key in parse_qs(query):
                _add(key, link, "GET")

        base = (base_url or "").rstrip("/")
        for finding in discovery_output.potential_vulns:
            loc = (finding.location or "").strip()
            params = [p.strip() for p in re.split(r"[,/|]", finding.parameter or "") if p.strip()]
            candidates: list[tuple[str, str]] = []
            for p in params:
                candidates.extend(param_targets.get(p.lower(), []))
            if not candidates:
                continue

            hints = self._PATH_HINTS.get(finding.vuln_type, [])
            best = None
            for hint in hints:
                for url, method in candidates:
                    if hint in urlparse(url).path.lower():
                        best = (url, method)
                        break
                if best:
                    break
            if not best:
                best = candidates[0]

            missing = (not loc) or loc in ("#",) or loc.rstrip("/") == base
            better = (
                hints
                and any(h in urlparse(best[0]).path.lower() for h in hints)
                and not any(h in loc.lower() for h in hints)
            )
            if missing or better or not loc.lower().startswith("http"):
                finding.location = best[0]

    def _expand_surface(self, request, discovery_output, web_analysis, recon_output, lp, cancel_event):
        """Build the complete, target-agnostic injection-point inventory.

        Combines three sources, in order: the LLM discovery findings (already
        enriched), tool-free active discovery (hidden endpoints + parameters),
        and an optional known-app profile's seed points. The whole crawled
        surface is then mapped to candidate (vuln_type, endpoint, parameter)
        test tasks so no input is silently dropped. Returns (inventory, profile).
        """
        base_url = request.url
        profile = detect_profile(base_url, web_analysis, recon_output)

        cookies = {}
        if request.credentials and request.credentials.cookies:
            cookies = dict(request.credentials.cookies)

        if not self._stop(cancel_event):
            try:
                set_progress("active discovery (hidden endpoints & parameters)")
                known_links = list(web_analysis.links) if web_analysis else []
                extra_findings, discovered_urls = ActiveDiscovery(self.config).run(
                    base_url, cookies=cookies, level=request.scan_level,
                    known_links=known_links, cancel_event=cancel_event,
                )
                if web_analysis is not None and discovered_urls:
                    for u in discovered_urls:
                        if u not in web_analysis.links:
                            web_analysis.links.append(u)
                discovery_output.potential_vulns.extend(extra_findings)
            except Exception as e:
                logger.warning(f"Active discovery skipped: {e}")

        if profile:
            try:
                discovery_output.potential_vulns.extend(profile.seed_findings(base_url))
            except Exception as e:
                logger.warning(f"Profile seeding failed: {e}")

        findings, inventory = map_attack_surface(
            web_analysis, base_url, existing=discovery_output.potential_vulns
        )
        discovery_output.potential_vulns = findings

        endpoints = len({(vt, url) for vt, url, _ in inventory})
        logger.info(
            "Attack surface: %d injection points, %d candidate (type,endpoint) pairs%s",
            len(findings), endpoints,
            f", profile={profile.name}" if profile else "",
        )
        return inventory, profile

    _DEFAULT_CREDS = [
        ("admin", "password"), ("admin", "admin"), ("administrator", "admin"),
        ("admin", "admin123"), ("root", "toor"), ("user", "password"),
    ]

    def _authenticate(self, request) -> dict:
        creds = request.credentials
        if creds and creds.cookies:
            return dict(creds.cookies)

        pairs = []
        if creds and (creds.username or creds.password):
            pairs.append((creds.username or "admin", creds.password or ""))
        pairs += [p for p in self._DEFAULT_CREDS if p not in pairs]

        base = request.url.rstrip("/")
        candidates = [
            base, base + "/login.php", base + "/login", base + "/index.php",
            base + "/admin", base + "/users/sign_in",
        ]
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 BingoScanner"})

        for login_url in candidates:
            try:
                resp = session.get(login_url, timeout=12, allow_redirects=True)
            except Exception:
                continue
            form = self._parse_login_form(resp.text, resp.url)
            if not form:
                continue
            is_dvwa = "dvwa" in resp.text.lower()
            if is_dvwa:
                self._dvwa_create_db(session, base)
            for user, pw in pairs:
                try:
                    refresh = self._parse_login_form(session.get(resp.url, timeout=12).text, resp.url) or form
                    data = dict(refresh["hidden"])
                    data[refresh["user_field"]] = user
                    data[refresh["pass_field"]] = pw
                    if refresh["submit"]:
                        data[refresh["submit"][0]] = refresh["submit"][1]
                    session.request(refresh["method"], refresh["action"], data=data, timeout=12, allow_redirects=True)
                    if self._login_ok(session, base):
                        logger.info("Auto-login succeeded with %s/%s", user, pw)
                        if is_dvwa:
                            self._dvwa_set_security(session, base)
                        cookies = session.cookies.get_dict()
                        if is_dvwa:
                            cookies.setdefault("security", "low")
                        return cookies
                except Exception:
                    continue
        return {}

    @staticmethod
    def _parse_login_form(html: str, page_url: str):
        for fhtml in re.findall(r"<form\b[^>]*>.*?</form>", html or "", re.I | re.S):
            if not re.search(r'type=["\']?password', fhtml, re.I):
                continue
            action_m = re.search(r'action=["\']([^"\']*)["\']', fhtml, re.I)
            method_m = re.search(r'method=["\']?(get|post)', fhtml, re.I)
            raw_action = action_m.group(1).strip() if action_m else ""
            action = page_url if raw_action in ("", "#") else urljoin(page_url, raw_action)
            method = (method_m.group(1).lower() if method_m else "post")
            user_field = pass_field = submit = None
            hidden = {}
            for inp in re.findall(r"<input\b[^>]*>", fhtml, re.I):
                tm = re.search(r'type=["\']?([a-zA-Z]+)', inp)
                typ = (tm.group(1).lower() if tm else "text")
                nm = re.search(r'name=["\']([^"\']+)["\']', inp)
                if not nm:
                    continue
                name = nm.group(1)
                vm = re.search(r'value=["\']([^"\']*)["\']', inp)
                value = vm.group(1) if vm else ""
                if typ == "password":
                    pass_field = name
                elif typ == "hidden":
                    hidden[name] = value
                elif typ in ("text", "email") and user_field is None:
                    user_field = name
                elif typ == "submit":
                    submit = (name, value or "Login")
            if pass_field and user_field:
                return {"action": action, "method": method, "user_field": user_field,
                        "pass_field": pass_field, "hidden": hidden, "submit": submit}
        return None

    @staticmethod
    def _login_ok(session, base: str) -> bool:
        try:
            body = session.get(base, timeout=12).text.lower()
            return 'type="password"' not in body and "type='password'" not in body
        except Exception:
            return False

    @staticmethod
    def _dvwa_tok(session, url):
        try:
            m = re.search(r"user_token['\"]\s+value=['\"]([0-9a-f]+)", session.get(url, timeout=12).text)
            return m.group(1) if m else ""
        except Exception:
            return ""

    @classmethod
    def _dvwa_create_db(cls, session, base: str):
        try:
            session.post(base + "/setup.php",
                         data={"create_db": "Create / Reset Database", "user_token": cls._dvwa_tok(session, base + "/setup.php")},
                         timeout=25)
        except Exception:
            pass

    @classmethod
    def _dvwa_set_security(cls, session, base: str):
        try:
            session.post(base + "/security.php",
                         data={"security": "low", "seclvl_submit": "Submit", "user_token": cls._dvwa_tok(session, base + "/security.php")},
                         timeout=12)
        except Exception:
            pass

    def _run_recon_parallel(self, request, memory, max_pages: int = 25):
        """Run ReconAgent and WebAnalyzer in parallel."""
        recon_output = None
        web_output = None

        web_analyzer = WebAnalyzer(self.config)
        web_analyzer.MAX_PAGES = max_pages
        recon_agent = ReconAgent(self.config)

        cookies = {}
        if request.credentials:
            cookies = request.credentials.cookies

        with ThreadPoolExecutor(max_workers=2) as executor:
            future_recon = executor.submit(recon_agent.run, request.url)
            future_web = executor.submit(web_analyzer.analyze, request.url, cookies)

            try:
                recon_output = future_recon.result(
                    timeout=self.config.agent_limits.recon_timeout
                )
                memory.set_recon(recon_output)
            except Exception as e:
                logger.error(f"Recon failed: {e}")
                memory.add_error(f"Recon: {e}")

            try:
                web_output = future_web.result(timeout=60)
                memory.set_web_analysis(web_output)
            except Exception as e:
                logger.error(f"Web analysis failed: {e}")
                memory.add_error(f"WebAnalysis: {e}")

        return recon_output, web_output

    def _exploit_parallel(
        self, request, vuln_types, discovery_output, memory, lp=None, cancel_event=None,
        inventory=None, profile=None,
    ) -> list[VulnerabilityFinding]:
        """Plan and exploit each vuln type in parallel."""
        lp = lp or self._LEVELS[2]
        inventory = inventory or []
        iter_mult = lp.get("iter_mult", 1.0)
        retry_rounds = lp.get("retry_rounds", 1)
        findings: list[VulnerabilityFinding] = []
        attempt_summaries: dict[str, str] = {}
        planner = PlannerAgent(self.config, self.rag_engine)

        vuln_evidence: dict[str, list] = {}
        for finding in discovery_output.potential_vulns:
            vt = finding.vuln_type
            vuln_evidence.setdefault(vt, []).append(finding)

        web_analysis = memory.get_web_analysis()
        cookie_str = ""
        if web_analysis and web_analysis.cookies:
            cookie_str = "; ".join(
                f"{k}={v}" for k, v in web_analysis.cookies.items()
            )

        site_map = ""
        if web_analysis:
            forms_desc = []
            for i, form in enumerate(web_analysis.forms):
                inputs_str = ", ".join(
                    inp.get("name", "?") for inp in form.inputs if inp.get("name")
                )
                page = form.page_url or "unknown"
                forms_desc.append(
                    f"  Form {i} on {page}: {form.method} {form.action} → inputs: [{inputs_str}]"
                )
            pages = [
                link for link in web_analysis.links
                if request.url.split("//")[-1].split("/")[0] in link
            ][:50]
            site_map = (
                "=== Discovered Forms ===\n"
                + "\n".join(forms_desc)
                + "\n\n=== Discovered Pages ===\n"
                + "\n".join(f"  {p}" for p in pages)
            )

        creds_str = ""
        if request.credentials:
            creds_str = request.credentials.model_dump_json()
        if cookie_str:
            creds_str += f"\nSession cookies (use with curl -b): {cookie_str}"

        def _plan_single(vuln_type: str):
            config_key = vuln_type
            if config_key not in EXPLOIT_CONFIGS:
                logger.warning(f"No exploit config for {vuln_type}, skipping")
                return None
            if self._stop(cancel_event):
                return None

            set_progress(f"planning attack for {vuln_type}")
            ev_list = vuln_evidence.get(vuln_type, [])
            tech_stack = ", ".join(discovery_output.technology_stack)

            form_methods = {}
            if web_analysis:
                for form in web_analysis.forms:
                    action_url = form.action or form.page_url or ""
                    form_methods[action_url] = form.method
                    if form.page_url:
                        form_methods[form.page_url] = form.method

            targets_desc = []
            for ev in ev_list:
                method = ""
                for furl, fmethod in form_methods.items():
                    if ev.location and (furl in ev.location or ev.location in furl):
                        method = fmethod
                        break
                method_str = f", HTTP Method: {method}" if method else ""
                targets_desc.append(
                    f"  - URL: {ev.location}, Parameter: {ev.parameter}{method_str}, "
                    f"Evidence: {ev.evidence}, Priority: {ev.priority}"
                )
            targets_str = "\n".join(targets_desc) if targets_desc else "  No specific targets; explore the site."

            primary = ev_list[0] if ev_list else None
            primary_url = primary.location if primary else request.url
            primary_param = primary.parameter if primary else ""
            primary_evidence = primary.evidence if primary else ""

            plan = planner.run(
                vuln_type=vuln_type,
                url=primary_url,
                parameter=primary_param,
                evidence=primary_evidence,
                tech_stack=tech_stack,
                previous_attempt=attempt_summaries.get(vuln_type, ""),
            )

            return {
                "vuln_type": vuln_type,
                "config_key": config_key,
                "plan": plan,
                "primary_url": primary_url,
                "primary_param": primary_param,
                "targets_str": targets_str,
            }

        def _exec_single(ctx) -> list[VulnerabilityFinding]:
            if not ctx or self._stop(cancel_event):
                return []
            vuln_type = ctx["vuln_type"]
            primary_url = ctx["primary_url"]
            primary_param = ctx["primary_param"]
            set_progress(f"exploiting {vuln_type}")

            rag_context = self.rag_engine.get_context(
                f"{vuln_type} exploitation", vuln_type=vuln_type
            )

            base_cfg = EXPLOIT_CONFIGS[ctx["config_key"]]
            vuln_config = dict(base_cfg)
            base_iter = base_cfg.get("max_iterations", self.config.agent_limits.exploit_max_iterations)
            vuln_config["max_iterations"] = max(6, int(base_iter * iter_mult))
            base_seconds = getattr(self.config.agent_limits, "exploit_max_seconds", 240)
            vuln_config["max_seconds"] = max(120, int(base_seconds * iter_mult))
            agent = BaseExploitAgent(
                self.config, vuln_config, memory, self.rag_engine,
                human_callback=self.human_callback, cancel_event=cancel_event,
            )

            profile_note = ""
            if profile:
                try:
                    sheet = profile.cheat_sheet()
                    if sheet:
                        profile_note = f"{sheet}\n\n"
                except Exception:
                    profile_note = ""

            full_context = (
                f"{profile_note}"
                f"{rag_context}\n\n"
                f"=== ALL Targets to Test for {vuln_type} ===\n"
                f"{ctx['targets_str']}\n\n"
                f"{site_map}"
            )

            result = agent.run(
                url=primary_url,
                plan=ctx["plan"].model_dump_json(),
                credentials=creds_str,
                rag_context=full_context,
            )
            attempt_summaries[vuln_type] = result.get("summary", "")

            return self._parse_exploit_output(
                vuln_type, primary_url, primary_param, result
            )

        def _exploit_single(vuln_type: str) -> list[VulnerabilityFinding]:
            return _exec_single(_plan_single(vuln_type))

        max_workers = lp.get("max_parallel") or self.config.agent_limits.max_parallel_agents
        max_workers = max(1, min(len(vuln_types), max_workers))

        def _run_wave(types):
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_exploit_single, vt): vt for vt in types}
                for future in as_completed(futures):
                    vt = futures[future]
                    try:
                        findings.extend(future.result(
                            timeout=self.config.agent_limits.recon_timeout * 2
                        ))
                    except Exception as e:
                        logger.error(f"Exploit failed for {vt}: {e}")
                        memory.add_error(f"Exploit({vt}): {e}")

        def _run_two_phase(types):
            logger.info(f"Planning phase — building attack plans for {len(types)} types")
            console_print(
                f"\n########## PLANNING PHASE — {len(types)} vulnerability types: "
                f"{', '.join(types)} ##########"
            )
            contexts = []
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_plan_single, vt): vt for vt in types}
                for future in as_completed(futures):
                    vt = futures[future]
                    try:
                        ctx = future.result(
                            timeout=self.config.agent_limits.planner_timeout * 3
                        )
                        if ctx:
                            contexts.append(ctx)
                    except Exception as e:
                        logger.error(f"Planning failed for {vt}: {e}")
                        memory.add_error(f"Plan({vt}): {e}")

            if self._stop(cancel_event):
                return
            logger.info(f"Exploitation phase — executing {len(contexts)} planned types")
            console_print(
                f"\n########## EXPLOITATION PHASE — executing {len(contexts)} planned types ##########"
            )
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_exec_single, ctx): ctx["vuln_type"] for ctx in contexts}
                for future in as_completed(futures):
                    vt = futures[future]
                    try:
                        findings.extend(future.result(
                            timeout=self.config.agent_limits.recon_timeout * 2
                        ))
                    except Exception as e:
                        logger.error(f"Exploit failed for {vt}: {e}")
                        memory.add_error(f"Exploit({vt}): {e}")

        def _gap_map():
            """Inventory injection points that are still unconfirmed, by type.

            Coverage is measured against the discovered attack surface, not a
            fixed target list — so this generalises to any application.
            """
            confirmed = {(f.vuln_type.value, normalize_url(f.url)) for f in findings}
            gaps: dict[str, set] = {}
            for vt, url, _param in inventory:
                if vt not in vuln_types or vt not in EXPLOIT_CONFIGS:
                    continue
                if (vt, url) in confirmed:
                    continue
                gaps.setdefault(vt, set()).add(url)
            return gaps

        _run_two_phase(vuln_types)

        rounds = 0
        while rounds < retry_rounds and not self._stop(cancel_event):
            gaps = _gap_map()
            if not gaps:
                break
            confirmed_types = {f.vuln_type.value for f in findings}
            partial = {vt: u for vt, u in gaps.items() if vt in confirmed_types}
            fresh = {vt: u for vt, u in gaps.items() if vt not in confirmed_types}
            retry = dict(partial)
            if rounds == 0:
                retry.update(fresh)
            if not retry:
                break
            before = len(findings)
            for vt, urls in retry.items():
                focus = "; ".join(sorted(urls)[:8])
                prev = attempt_summaries.get(vt, "")
                attempt_summaries[vt] = (
                    f"{prev}\nSTILL UNCONFIRMED — focus testing on these endpoints "
                    f"and try researched bypasses: {focus}"
                ).strip()
            logger.info(
                f"Completeness critic round {rounds + 1}/{retry_rounds}: retrying "
                f"{len(retry)} type(s), {sum(len(u) for u in retry.values())} surfaces: {list(retry)}"
            )
            console_print(
                f"\n########## COMPLETENESS CRITIC — round {rounds + 1}: "
                f"{len(retry)} type(s) with untested surfaces: {', '.join(retry)} ##########"
            )
            _run_wave(list(retry.keys()))
            rounds += 1
            if len(findings) == before:
                break

        unique: dict[tuple, VulnerabilityFinding] = {}
        for f in findings:
            path = urlparse(f.url).path.rstrip("/")
            key = (f.vuln_type.value, path)
            if key not in unique:
                unique[key] = f
        return list(unique.values())

    _SEVERITY_MAP = {
        "sqli": Severity.CRITICAL,
        "command_injection": Severity.CRITICAL,
        "xss": Severity.HIGH,
        "lfi": Severity.HIGH,
        "rfi": Severity.HIGH,
        "file_upload": Severity.HIGH,
        "csrf": Severity.MEDIUM,
        "brute_force": Severity.MEDIUM,
        "open_redirect": Severity.MEDIUM,
    }

    _EVIDENCE_MARKERS = [
        r"root:x:0:0:", r"www-data", r"uid=\d+\(",
        r"<script>alert", r"onerror=alert", r"<img\s+src=x",
        r"syntax.*?error.*?SQL", r"UNION SELECT", r"You have an error in your SQL",
        r"First name:.*Surname:", r"Password Changed",
        r"succesfully uploaded", r"successfully uploaded",
        r"Welcome to the password protected area",
    ]

    @classmethod
    def _parse_exploit_output(
        cls, vuln_type: str, url: str, parameter: str, result: dict
    ) -> list[VulnerabilityFinding]:
        """Parse the agent output into structured findings.

        Supports MULTIPLE confirmed endpoints in one Final Answer: the prompt
        asks the agent to emit one ``STATUS: ...`` block per vulnerable target,
        and we build a finding per CONFIRMED block. Falls back to a single
        evidence-marker-based finding when the agent did not use the format.
        """
        output = result.get("output", "")
        if not output or not result.get("success"):
            return []

        try:
            vt_enum = VulnType(vuln_type)
        except ValueError:
            vt_enum = VulnType.OTHER

        blocks = re.split(r"(?=^\s*STATUS:)", output, flags=re.MULTILINE)
        findings: list[VulnerabilityFinding] = []
        for block in blocks:
            if not re.search(r"STATUS:\s*CONFIRMED", block, re.IGNORECASE):
                continue
            if re.search(r"STATUS:\s*NOT[_\s]?VULNERABLE", block, re.IGNORECASE):
                continue
            findings.append(
                cls._build_finding(vt_enum, vuln_type, url, parameter, block, output)
            )

        if not findings:
            negated = re.search(
                r"(?:not|no|none|unable|failed|could not|cannot|didn'?t)"
                r"[\s\w]*(?:confirmed|vulnerable|exploited)",
                output,
                re.IGNORECASE,
            )
            has_evidence = any(
                re.search(m, output, re.IGNORECASE) for m in cls._EVIDENCE_MARKERS
            )
            if has_evidence and not negated:
                findings.append(
                    cls._build_finding(vt_enum, vuln_type, url, parameter, output, output)
                )

        return findings

    @classmethod
    def _build_finding(
        cls, vt_enum, vuln_type, default_url, default_param, block, full_output
    ) -> VulnerabilityFinding:
        """Extract structured fields from a single CONFIRMED block."""
        vuln_url, vuln_param = default_url, default_param
        payload = command = evidence_snippet = poc_url = ""
        field_patterns = {
            "payload": r"^PAYLOAD:\s*(.+)$",
            "command": r"^COMMAND:\s*(.+)$",
            "evidence": r"^EVIDENCE:\s*(.+)$",
            "url": r"^URL:\s*(https?://\S+)$",
            "parameter": r"^PARAMETER:\s*(\S+)$",
            "poc": r"^POC_URL:\s*(https?://\S+)$",
        }
        for key, pattern in field_patterns.items():
            m = re.search(pattern, block, re.MULTILINE | re.IGNORECASE)
            if not m:
                continue
            val = m.group(1).strip()
            if key == "payload":
                payload = val
            elif key == "command":
                command = val
            elif key == "evidence":
                evidence_snippet = val
            elif key == "url":
                vuln_url = val
            elif key == "parameter":
                vuln_param = val
            elif key == "poc":
                poc_url = val

        if not payload:
            curl_match = re.search(r"(curl\s+.{20,}?)(?:\n|$)", block, re.IGNORECASE)
            if curl_match:
                payload = curl_match.group(1).strip()[:500]

        if not poc_url and payload and vuln_param and vuln_url.lower().startswith("http"):
            cmd_l = command.lower()
            bad_param = vuln_param.strip().lower() in ("", "unknown", "none", "n/a")
            bad_payload = (
                len(payload) > 160
                or "\n" in payload
                or any(t in payload for t in ("import ", "requests.", "print(", "for ", "while ", "curl "))
            )
            get_like = (
                "curl -g" in cmd_l or "--data-urlencode" in cmd_l
                or vuln_type in ("sqli", "xss", "lfi", "rfi", "open_redirect", "brute_force", "idor")
            )
            if get_like and not bad_param and not bad_payload:
                base = vuln_url.split("#")[0]
                sep = "&" if "?" in base else "?"
                poc_url = f"{base}{sep}{vuln_param}={quote(payload, safe=_POC_SAFE)}"

        proof_parts = []
        if payload:
            proof_parts.append(f"Payload: {payload}")
        if command:
            proof_parts.append(f"Command: {command}")
        if vuln_param:
            proof_parts.append(f"Parameter: {vuln_param}")
        if poc_url:
            proof_parts.append(f"PoC: {poc_url}")
        proof_parts.append(f"Output: {evidence_snippet or block[:1500]}")

        return VulnerabilityFinding(
            vuln_type=vt_enum,
            severity=cls._SEVERITY_MAP.get(vuln_type, Severity.HIGH),
            confidence=Confidence.CONFIRMED,
            url=vuln_url,
            parameter=vuln_param,
            payload=payload,
            poc_url=poc_url,
            evidence="\n".join(proof_parts)[:2000],
            tool_output=full_output[:5000],
        )
