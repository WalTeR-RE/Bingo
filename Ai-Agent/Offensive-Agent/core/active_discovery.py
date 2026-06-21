import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from ..models.schemas import DiscoveryFinding
from ..utils.logger import get_logger
from . import surface

logger = get_logger("active_discovery")

_UA = "Mozilla/5.0 (X11; Linux x86_64) BingoScanner"
_CANARY = "bq9z7xk1"

_LEVEL = {
    1: {"paths": 0, "param_endpoints": 0, "params": 0, "workers": 8, "budget": 0},
    2: {"paths": 350, "param_endpoints": 6, "params": 48, "workers": 16, "budget": 75},
    3: {"paths": 2000, "param_endpoints": 14, "params": 90, "workers": 24, "budget": 180},
}

_BUILTIN_PATHS = [
    "admin", "admin/", "administrator", "admin.php", "login", "login.php", "signin",
    "register", "user", "users", "account", "profile", "dashboard", "panel", "cpanel",
    "config", "config.php", "configuration.php", "settings", "setup", "install",
    "phpinfo.php", "info.php", "test.php", "test", "debug", "status", "health",
    "api", "api/", "api/v1", "api/v2", "graphql", "rest", "swagger", "swagger-ui",
    "swagger.json", "openapi.json", "api-docs", "console", "actuator", "actuator/env",
    "actuator/health", "metrics", "server-status", "server-info", "phpmyadmin",
    "pma", "adminer.php", "db", "database", "backup", "backups", "backup.zip",
    "backup.sql", "dump.sql", "db.sql", "site.tar.gz", "www.zip", "old", "tmp",
    "temp", "uploads", "upload", "files", "file", "images", "img", "assets", "static",
    "includes", "include", "lib", "vendor", "node_modules", "src", "app", "cgi-bin",
    "wp-admin", "wp-login.php", "wp-config.php", "wp-content", "wp-json", "xmlrpc.php",
    "robots.txt", "sitemap.xml", "humans.txt", "crossdomain.xml", "security.txt",
    ".env", ".env.bak", ".git/HEAD", ".git/config", ".gitignore", ".svn/entries",
    ".htaccess", ".htpasswd", "web.config", ".DS_Store", "composer.json",
    "package.json", "Dockerfile", "docker-compose.yml", ".aws/credentials",
    "id_rsa", "credentials", "secret", "secrets", "private", "internal", "hidden",
    "search", "search.php", "comment", "comments", "feedback", "contact", "contact.php",
    "redirect", "redirect.php", "proxy", "proxy.php", "fetch", "download", "download.php",
    "view", "view.php", "page", "page.php", "index.php", "home", "main", "portal",
    "logout", "reset", "forgot", "change-password", "verify", "token", "session",
    "report", "reports", "export", "import", "data", "json", "xml", "rss", "feed",
    "manage", "management", "control", "system", "monitor", "logs", "log", "error.log",
    "access.log", "shell", "cmd", "exec", "run", "ping", "dns", "whois",
]

_BUILTIN_PARAMS = [
    "id", "page", "file", "path", "dir", "url", "redirect", "next", "return", "dest",
    "q", "query", "search", "s", "keyword", "name", "user", "username", "email",
    "cmd", "command", "exec", "ip", "host", "domain", "ping", "lang", "language",
    "view", "action", "do", "func", "module", "template", "tpl", "include", "inc",
    "load", "read", "show", "content", "data", "item", "category", "cat", "type",
    "sort", "order", "filter", "limit", "offset", "ref", "callback", "feed", "target",
    "doc", "document", "report", "format", "key", "token", "code", "value", "input",
    "msg", "message", "comment", "title", "body", "text", "src", "img", "image",
    "uri", "link", "goto", "out", "continue", "site", "fetch", "proxy", "to",
]

_SENSITIVE = {
    ".env", ".env.bak", ".git/head", ".git/config", ".svn/entries", ".htpasswd",
    ".aws/credentials", "id_rsa", "wp-config.php", "config.php", "phpinfo.php",
    "info.php", "server-status", "server-info", "backup.zip", "backup.sql",
    "dump.sql", "db.sql", "web.config", ".ds_store", "actuator/env", "credentials",
}


class ActiveDiscovery:
    """Tool-free content + parameter discovery to widen the attack surface.

    Uses only `requests`, so it runs anywhere (no ffuf/gobuster/arjun required).
    Finds unlinked endpoints and hidden parameters that a crawl alone misses, then
    maps them to candidate injection points with the shared surface heuristics.
    """

    def __init__(self, config):
        self.config = config

    def run(self, base_url, cookies=None, level=2, known_links=None, cancel_event=None):
        limits = _LEVEL.get(int(level) if str(level).isdigit() else 2, _LEVEL[2])
        if limits["budget"] <= 0:
            return [], []
        deadline = time.time() + limits["budget"]
        session = requests.Session()
        session.headers.update({"User-Agent": _UA})
        if cookies:
            for k, v in cookies.items():
                session.cookies.set(k, v)

        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        findings: list[DiscoveryFinding] = []
        discovered_urls: list[str] = []

        try:
            discovered_urls, content_findings = self._content_discovery(
                session, origin, limits, deadline, cancel_event
            )
            findings.extend(content_findings)
        except Exception as e:
            logger.warning("Content discovery failed: %s", e)

        try:
            param_findings = self._param_discovery(
                session, origin, base_url, known_links or [], discovered_urls,
                limits, deadline, cancel_event
            )
            findings.extend(param_findings)
        except Exception as e:
            logger.warning("Parameter discovery failed: %s", e)

        logger.info(
            "Active discovery: %d endpoints, %d injection points found",
            len(discovered_urls), len(findings),
        )
        return surface.dedup_findings(findings), discovered_urls

    def _load_wordlist(self, cap: int) -> list[str]:
        paths = []
        wl = getattr(self.config.paths, "wordlists", None)
        candidates = []
        if wl is not None:
            candidates.append(getattr(wl, "common", ""))
        candidates += [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
        for cand in candidates:
            if not cand:
                continue
            p = Path(cand)
            if p.exists():
                try:
                    for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
                        ln = ln.strip().lstrip("/")
                        if ln and not ln.startswith("#"):
                            paths.append(ln)
                        if len(paths) >= cap:
                            break
                    logger.info("Content discovery wordlist: %s (%d entries)", cand, len(paths))
                    break
                except OSError:
                    continue
        merged = list(dict.fromkeys(_BUILTIN_PATHS + paths))
        return merged[:cap] if cap else merged

    def _fingerprint_404(self, session, origin):
        marks = set()
        for token in ("bingo_nope_4d51a", "zzz_404_probe_x"):
            try:
                r = session.get(f"{origin}/{token}", timeout=5, allow_redirects=False)
                marks.add((r.status_code, len(r.content) // 64))
            except requests.RequestException:
                marks.add((404, 0))
        return marks

    def _content_discovery(self, session, origin, limits, deadline, cancel_event):
        cap = limits["paths"]
        if cap <= 0:
            return [], []
        wordlist = self._load_wordlist(cap)
        not_found = self._fingerprint_404(session, origin)
        discovered: list[str] = []
        findings: list[DiscoveryFinding] = []

        def probe(path):
            if time.time() > deadline or _stopped(cancel_event):
                return None
            url = f"{origin}/{path.lstrip('/')}"
            try:
                r = session.get(url, timeout=5, allow_redirects=False)
            except requests.RequestException:
                return None
            sig = (r.status_code, len(r.content) // 64)
            if r.status_code in (404, 400) or sig in not_found:
                return None
            if r.status_code in (200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500):
                return (url, path.lstrip("/").lower(), r.status_code)
            return None

        ex = ThreadPoolExecutor(max_workers=limits["workers"])
        try:
            futures = [ex.submit(probe, p) for p in wordlist]
            for fut in as_completed(futures):
                if time.time() > deadline or _stopped(cancel_event):
                    break
                res = fut.result()
                if not res:
                    continue
                url, low, status = res
                discovered.append(url)
                if low in _SENSITIVE and status in (200, 301, 302):
                    findings.append(
                        DiscoveryFinding(
                            vuln_type="misconfiguration",
                            location=url,
                            parameter="",
                            evidence=f"Sensitive path exposed: {url} (HTTP {status}).",
                            priority="high",
                        )
                    )
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        return discovered, findings

    def _param_discovery(self, session, origin, base_url, known_links, discovered,
                         limits, deadline, cancel_event):
        cap_ep = limits["param_endpoints"]
        cap_p = limits["params"]
        if cap_ep <= 0 or cap_p <= 0:
            return []

        endpoints = []
        seen = set()
        for url in [base_url] + list(known_links) + list(discovered):
            base = url.split("?")[0]
            low = base.lower()
            if base in seen:
                continue
            if low.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                             ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip")):
                continue
            seen.add(base)
            endpoints.append(base)
            if len(endpoints) >= cap_ep:
                break

        params = _BUILTIN_PARAMS[:cap_p]
        findings: list[DiscoveryFinding] = []

        def probe(endpoint, param):
            if time.time() > deadline or _stopped(cancel_event):
                return None
            try:
                r = session.get(endpoint, params={param: _CANARY}, timeout=5)
            except requests.RequestException:
                return None
            if _CANARY in r.text:
                return (endpoint, param)
            return None

        tasks = [(e, p) for e in endpoints for p in params]
        ex = ThreadPoolExecutor(max_workers=limits["workers"])
        try:
            futures = [ex.submit(probe, e, p) for e, p in tasks]
            for fut in as_completed(futures):
                if time.time() > deadline or _stopped(cancel_event):
                    break
                res = fut.result()
                if not res:
                    continue
                endpoint, param = res
                for vt in surface.classes_for_param(param, ""):
                    findings.append(
                        DiscoveryFinding(
                            vuln_type=vt,
                            location=f"{endpoint}?{param}={_CANARY}",
                            parameter=param,
                            evidence=f"Hidden parameter '{param}' reflects at {endpoint} "
                            f"(found by active probing).",
                            priority=surface.priority_for(vt),
                        )
                    )
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        return findings


def _stopped(cancel_event) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())
