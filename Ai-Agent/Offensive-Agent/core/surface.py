from urllib.parse import parse_qs, urlparse

from ..models.schemas import DiscoveryFinding

_FILE_PARAMS = {
    "page", "file", "path", "doc", "document", "filename", "fn", "dir", "folder",
    "include", "inc", "require", "template", "tpl", "view", "load", "read", "show",
    "download", "content", "layout", "module", "lang", "language", "locale", "theme",
    "style", "pdf", "report", "img", "image", "pg", "src",
}
_URL_PARAMS = {
    "url", "uri", "link", "redirect", "redir", "return", "returnurl", "return_url",
    "returnto", "next", "dest", "destination", "continue", "goto", "out", "target",
    "callback", "data", "feed", "host", "site", "domain", "forward", "to", "rurl",
    "image_url", "fetch", "open", "navigation", "path_url", "u", "q_url", "webhook",
}
_CMD_PARAMS = {
    "cmd", "command", "exec", "execute", "ping", "ip", "ipaddress", "addr", "host",
    "hostname", "domain", "dns", "run", "action", "do", "func", "function", "process",
    "system", "shell", "code", "task", "job", "option",
}
_SSTI_PARAMS = {
    "template", "tpl", "tmpl", "render", "preview", "theme", "layout", "engine",
    "twig", "mustache", "velocity", "freemarker", "handlebars",
}
_TOKEN_NAMES = {
    "csrf", "csrf_token", "csrftoken", "user_token", "authenticity_token", "_token",
    "__requestverificationtoken", "nonce", "_csrf", "csrfmiddlewaretoken", "xsrf",
}
_STATE_HINTS = (
    "password", "pass", "pwd", "email", "new", "change", "update", "delete", "remove",
    "amount", "transfer", "balance", "role", "admin", "enable", "disable", "create",
    "add", "edit", "save", "settings", "config", "grant", "approve",
)
_SKIP_TYPES = {"submit", "button", "image", "reset"}
_GENERIC = ("sqli", "xss")
_SIGNATURE_CLASSES = {
    "lfi", "rfi", "ssrf", "open_redirect", "command_injection", "idor", "ssti",
    "file_upload",
}


def _norm(value: str) -> str:
    return (value or "").strip().lower()


def normalize_url(url: str) -> str:
    return (url or "").split("#")[0].rstrip("/")


_u = normalize_url


def classes_for_param(name: str, input_type: str = "") -> set:
    """Map a single parameter to the vuln classes worth testing on it.

    Heuristics hold for any web application: every free-text parameter is worth
    an SQLi + XSS probe, and the name signatures add the injection classes that a
    parameter of that shape commonly exposes. No target-specific knowledge.
    """
    it = _norm(input_type)
    if it == "file":
        return {"file_upload"}
    if it in _SKIP_TYPES:
        return set()
    n = _norm(name)
    if not n:
        return set()
    out = set(_GENERIC)
    if n in _FILE_PARAMS:
        out.add("lfi")
    if n in _URL_PARAMS:
        out.update(("ssrf", "open_redirect"))
    if n in _CMD_PARAMS:
        out.add("command_injection")
    if n in _SSTI_PARAMS:
        out.add("ssti")
    return out


def priority_for(vuln_type: str) -> str:
    return "high" if vuln_type in _SIGNATURE_CLASSES else "medium"


def _form_has_token(form) -> bool:
    return any(_norm(inp.get("name")) in _TOKEN_NAMES for inp in form.inputs)


def _form_is_password(form) -> bool:
    return any(_norm(inp.get("type")) == "password" for inp in form.inputs)


def _form_is_upload(form) -> bool:
    return any(_norm(inp.get("type")) == "file" for inp in form.inputs)


def _form_is_state_changing(form) -> bool:
    if (form.method or "GET").upper() == "POST":
        writable = [
            inp for inp in form.inputs
            if _norm(inp.get("type")) not in _SKIP_TYPES | {"hidden"}
        ]
        if writable:
            return True
    for inp in form.inputs:
        name = _norm(inp.get("name"))
        if any(h in name for h in _STATE_HINTS):
            return True
    return False


def _user_field(form) -> str:
    for inp in form.inputs:
        if _norm(inp.get("type")) in ("text", "email") and inp.get("name"):
            return inp.get("name")
    return "username"


def dedup_findings(findings: list) -> list:
    seen = set()
    unique = []
    for f in findings:
        key = (f.vuln_type, _norm(f.parameter), _u(f.location))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique


def map_attack_surface(web_analysis, base_url: str, existing: list = None):
    """Turn the crawled attack surface into a complete per-point test list.

    Returns (findings, inventory):
      - findings: DiscoveryFinding objects (existing ones preserved, deduplicated),
        one per (vuln_type, endpoint, parameter) injection point.
      - inventory: list of (vuln_type, normalized_url, parameter) tuples — the full
        candidate set used later to measure coverage and drive gap retries.
    """
    findings = list(existing or [])
    seen = {(f.vuln_type, _norm(f.parameter), _u(f.location)) for f in findings}

    def add(vuln_type: str, url: str, param: str, evidence: str = ""):
        nk = _u(url)
        key = (vuln_type, _norm(param), nk)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            DiscoveryFinding(
                vuln_type=vuln_type,
                location=url,
                parameter=param or "",
                evidence=evidence
                or f"Parameter '{param}' at {url} is an injection point for "
                f"{vuln_type} (mapped from crawled attack surface).",
                priority=priority_for(vuln_type),
            )
        )

    def _finalize():
        deduped = dedup_findings(findings)
        inv = [
            (f.vuln_type, normalize_url(f.location), _norm(f.parameter))
            for f in deduped
        ]
        return deduped, inv

    if not web_analysis:
        return _finalize()

    for form in web_analysis.forms:
        url = form.action or form.page_url or base_url
        method = (form.method or "GET").upper()
        for inp in form.inputs:
            name = inp.get("name", "")
            for vt in classes_for_param(name, inp.get("type", "")):
                add(vt, url, name)
        if _form_is_password(form):
            uf = _user_field(form)
            add("brute_force", url, uf,
                f"Login form at {url} ({method}) — credential brute force.")
        if _form_is_upload(form):
            add("file_upload", url, "",
                f"File upload form at {url} ({method}) — unrestricted upload.")
        if _form_is_state_changing(form) and not _form_has_token(form):
            add("csrf", url, "",
                f"State-changing form at {url} ({method}) has no anti-CSRF token.")

    for link in web_analysis.links:
        query = urlparse(link).query
        if not query:
            continue
        for key in parse_qs(query):
            for vt in classes_for_param(key, ""):
                add(vt, link, key)

    return _finalize()
