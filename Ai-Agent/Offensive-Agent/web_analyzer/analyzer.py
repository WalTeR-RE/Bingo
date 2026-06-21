from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright

from ..models.schemas import FormInfo, WebAnalysisOutput
from ..utils.logger import get_logger

logger = get_logger("web_analyzer")

class WebAnalyzer:
    """Playwright-based web page analysis — extracts forms, links, headers, cookies.

    Crawls the target URL and follows same-origin links (up to max_pages) to
    discover forms, input fields, and other attack-surface elements across the
    entire application — not just the landing page.
    """

    MAX_PAGES = 25
    SKIP_PATTERNS = ("logout", "signout", "sign-out", "logoff", "/logout.php")

    def __init__(self, config):
        self.config = config

    def analyze(self, url: str, cookies: dict = None) -> WebAnalysisOutput:
        logger.info(f"Analyzing: {url}")
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)

                if cookies:
                    cookie_list = [
                        {"name": k, "value": v, "url": url}
                        for k, v in cookies.items()
                    ]
                    context.add_cookies(cookie_list)

                page = context.new_page()

                parsed_origin = urlparse(url)
                origin = f"{parsed_origin.scheme}://{parsed_origin.netloc}"

                visited: set[str] = set()
                to_visit: list[str] = [url]

                all_forms: list[FormInfo] = []
                all_links: list[str] = []
                all_scripts: list[str] = []
                all_cookies: dict[str, str] = {}
                all_headers: dict[str, str] = {}
                all_page_text: list[str] = []
                all_raw_html: list[str] = []
                title = ""
                total_html_len = 0

                while to_visit and len(visited) < self.MAX_PAGES:
                    current_url = to_visit.pop(0)
                    current_url = current_url.split("#")[0]
                    if current_url in visited:
                        continue
                    if any(p in current_url.lower() for p in self.SKIP_PATTERNS):
                        continue
                    visited.add(current_url)

                    try:
                        response = page.goto(
                            current_url,
                            wait_until="domcontentloaded",
                            timeout=15000,
                        )
                    except Exception as nav_err:
                        logger.warning(f"Navigation failed for {current_url}: {nav_err}")
                        continue

                    if len(visited) == 1:
                        title = page.title()
                        if response:
                            all_headers = dict(response.headers)

                    page_forms = self._extract_forms(page, current_url)
                    all_forms.extend(page_forms)

                    page_links = self._extract_links(page)
                    for link in page_links:
                        abs_link = urljoin(current_url, link)
                        abs_link = abs_link.split("#")[0]
                        if abs_link not in all_links:
                            all_links.append(abs_link)
                        if (
                            abs_link not in visited
                            and abs_link not in to_visit
                            and urlparse(abs_link).netloc == parsed_origin.netloc
                        ):
                            to_visit.append(abs_link)

                    all_scripts.extend(
                        s for s in self._extract_scripts(page)
                        if s not in all_scripts
                    )

                    all_cookies.update(
                        {c["name"]: c["value"] for c in context.cookies()}
                    )

                    try:
                        text = page.inner_text("body")[:3000]
                        all_page_text.append(
                            f"--- {current_url} ---\n{text}"
                        )
                    except Exception:
                        pass

                    try:
                        html = page.content()
                        chunk = html[: max(0, 30000 - total_html_len)]
                        if chunk:
                            all_raw_html.append(
                                f"<!-- {current_url} -->\n{chunk}"
                            )
                            total_html_len += len(chunk)
                    except Exception:
                        pass

                browser.close()

                result = WebAnalysisOutput(
                    url=url,
                    title=title,
                    forms=all_forms,
                    links=all_links[:300],
                    scripts=all_scripts[:50],
                    cookies=all_cookies,
                    headers=all_headers,
                    page_text="\n".join(all_page_text)[:8000],
                    raw_html="\n".join(all_raw_html)[:30000],
                )

                logger.info(
                    f"Crawl complete: {len(visited)} pages, "
                    f"{len(result.forms)} forms, {len(result.links)} links"
                )
                return result
        except Exception as e:
            logger.error(f"Web analysis failed: {e}")
            return WebAnalysisOutput(url=url)

    @staticmethod
    def _extract_forms(page, page_url: str = "") -> list[FormInfo]:
        forms = []
        try:
            for form in page.query_selector_all("form"):
                inputs = []
                for inp in form.query_selector_all("input, select, textarea"):
                    inputs.append(
                        {
                            "name": inp.get_attribute("name") or "",
                            "type": inp.get_attribute("type") or "text",
                            "value": inp.get_attribute("value") or "",
                            "id": inp.get_attribute("id") or "",
                        }
                    )
                raw_action = (form.get_attribute("action") or "").strip()
                if raw_action in ("", "#") or raw_action.lower().startswith("javascript:"):
                    resolved_action = page_url
                else:
                    resolved_action = urljoin(page_url, raw_action)
                forms.append(
                    FormInfo(
                        action=resolved_action,
                        method=(form.get_attribute("method") or "GET").upper(),
                        inputs=inputs,
                        page_url=page_url,
                    )
                )
        except Exception:
            pass
        return forms

    @staticmethod
    def _extract_links(page) -> list[str]:
        try:
            return page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )[:200]
        except Exception:
            return []

    @staticmethod
    def _extract_scripts(page) -> list[str]:
        try:
            return page.eval_on_selector_all(
                "script[src]", "els => els.map(e => e.src)"
            )[:50]
        except Exception:
            return []
