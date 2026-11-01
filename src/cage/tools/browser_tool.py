from __future__ import annotations

import json
import time
from pathlib import Path

from cage.tools.base import BaseTool


class BrowserFetchTool(BaseTool):
    """
    Headless Chromium fetch via Playwright.
    - Executes JavaScript
    - Waits for network idle (solves most Cloudflare challenges)
    - Persists cookies for session continuity
    - Saves screenshots + HTML for evidence
    """

    DEFAULT_TIMEOUT_MS = 30_000

    @property
    def name(self) -> str:
        return "browser_fetch"

    @property
    def description(self) -> str:
        return (
            "Fetch a URL with a real headless Chromium browser. "
            "Executes JavaScript, solves Cloudflare/Akamai challenges, "
            "returns rendered DOM. Use this when curl/nmap return 403/503 "
            "or 'Checking your browser' or 'Access Denied'."
        )

    def execute(self, arguments: dict) -> dict:
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
        except ImportError:
            return {
                "status": "error",
                "error": (
                    "Playwright not installed. Run:\n"
                    "  pip install playwright --break-system-packages\n"
                    "  playwright install chromium\n"
                    "  playwright install-deps chromium"
                ),
            }

        url = str(arguments.get("url", "")).strip()
        if not url.startswith(("http://", "https://")):
            return {"status": "error", "error": f"invalid url: {url}"}

        wait_for = str(arguments.get("wait_for", "networkidle"))
        if wait_for not in ("load", "domcontentloaded", "networkidle", "commit"):
            wait_for = "networkidle"
        timeout_ms = int(arguments.get("timeout_ms", self.DEFAULT_TIMEOUT_MS))
        want_screenshot = bool(arguments.get("screenshot", False))
        save_html_path = arguments.get("save_html")
        cookies_in = arguments.get("cookies_in")
        cookies_out = arguments.get("cookies_out")
        user_agent = str(
            arguments.get(
                "user_agent",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            )
        )

        t0 = time.time()

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-blink-features=AutomationControlled",
                        "--disable-dev-shm-usage",
                    ],
                )
                context = browser.new_context(
                    user_agent=user_agent,
                    viewport={"width": 1440, "height": 900},
                    ignore_https_errors=True,
                    locale="en-US",
                )

                if cookies_in and Path(cookies_in).exists():
                    try:
                        cookies = json.loads(Path(cookies_in).read_text())
                        if isinstance(cookies, list):
                            context.add_cookies(cookies)
                    except Exception:
                        pass

                page = context.new_page()

                page.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    window.chrome = { runtime: {} };
                    Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
                    Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
                """)

                response = None
                try:
                    response = page.goto(url, wait_until=wait_for, timeout=timeout_ms)
                except PWTimeout:
                    response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

                http_status = response.status if response else 0
                final_url = page.url

                content_lower = page.content().lower()
                if any(k in content_lower for k in ("checking your browser", "cf-browser-verification")):
                    try:
                        page.wait_for_function(
                            "() => !document.body.innerText.includes('Checking')",
                            timeout=15_000,
                        )
                        http_status = 200
                        final_url = page.url
                    except PWTimeout:
                        pass

                title = page.title() or ""
                body_text = ""
                try:
                    if page.query_selector("body"):
                        body_text = page.inner_text("body")
                except Exception:
                    pass
                html = ""
                try:
                    html = page.content()
                except Exception:
                    pass

                cookies_path = None
                if cookies_out:
                    try:
                        Path(cookies_out).parent.mkdir(parents=True, exist_ok=True)
                        Path(cookies_out).write_text(json.dumps(context.cookies()))
                        cookies_path = str(cookies_out)
                    except Exception:
                        cookies_path = None

                screenshot_path = None
                if want_screenshot:
                    screenshot_path = f"/tmp/cage_shot_{int(time.time() * 1000)}.png"
                    try:
                        page.screenshot(path=screenshot_path, full_page=True)
                    except Exception:
                        screenshot_path = None

                if save_html_path:
                    try:
                        Path(save_html_path).parent.mkdir(parents=True, exist_ok=True)
                        Path(save_html_path).write_text(html)
                    except Exception:
                        pass

                browser.close()

        except PWTimeout:
            return {
                "status": "error",
                "error": f"Playwright timeout after {timeout_ms}ms navigating {url}",
            }
        except Exception as e:
            return {
                "status": "error",
                "error": f"Playwright error: {type(e).__name__}: {str(e)[:300]}",
            }

        elapsed = time.time() - t0

        return {
            "status": "ok",
            "url": final_url,
            "http_status": http_status,
            "title": title,
            "body_length": len(body_text),
            "html_length": len(html),
            "body_text": body_text[:8000],
            "html": html[:15000],
            "screenshot_path": screenshot_path,
            "cookies_path": cookies_path,
            "elapsed_s": round(elapsed, 2),
        }
