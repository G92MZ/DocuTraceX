"""Page screenshots with headless Chromium (Playwright), JavaScript always OFF.

Run as a separate process with a time limit:

    python -m docutracex.netcheck.shot offline <page.html> <out.png>
    python -m docutracex.netcheck.shot live <url> <out.png> [proxy_url] [user_agent] [strict]

- ``offline``: renders the HTML already downloaded, with *every* network
  request blocked — contacts nobody.
- ``live``: loads the URL with its images/CSS (through the proxy), still
  without JavaScript, so the page looks as the victim would see it.

Chromium is provisioned under ``tools/playwright`` at install time.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ..config import settings

VIEWPORT = {"width": 1280, "height": 900}
GOTO_TIMEOUT_MS = 60000  # live page load (slow hosts); the whole process is capped by the caller


def browsers_path() -> Path:
    return settings.tools_dir / "playwright"


def env() -> dict[str, str]:
    e = dict(os.environ)
    if browsers_path().is_dir():
        e["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers_path())
    return e


def _pw_proxy(proxy: str | None) -> dict[str, str] | None:
    if not proxy:
        return None
    p = urlsplit(proxy)
    scheme = "socks5" if p.scheme.startswith("socks5") else p.scheme
    out = {"server": f"{scheme}://{p.hostname}:{p.port}"}
    if p.username:
        out["username"] = unquote(p.username)
        out["password"] = unquote(p.password or "")
    return out


def _fallback_executable() -> str | None:
    """Any Chromium already on disk (when Playwright's expected build is missing)."""
    env = os.environ.get("DOCUTRACEX_CHROMIUM")
    if env and Path(env).is_file():
        return env
    roots = [browsers_path(), Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or "/nonexistent")]
    for root in roots:
        for pat in ("chromium-*/chrome-linux/chrome", "chromium-*/chrome-win/chrome.exe",
                    "chromium-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium", "chromium/chrome"):
            for c in sorted(root.glob(pat), reverse=True):
                if c.is_file():
                    return str(c)
    return None


def _launch(p, proxy):
    try:
        return p.chromium.launch(proxy=proxy)
    except Exception:
        exe = _fallback_executable()
        if not exe:
            raise
        return p.chromium.launch(proxy=proxy, executable_path=exe)


def main(argv: list[str]) -> int:
    from playwright.sync_api import sync_playwright

    mode, target, out = argv[0], argv[1], argv[2]
    proxy = argv[3] if len(argv) > 3 and argv[3] else None
    ua = argv[4] if len(argv) > 4 and argv[4] else None
    strict = len(argv) > 5 and argv[5] == "strict"  # free (untrusted) proxy: never accept a bad certificate
    res = {"ok": False, "mode": mode}
    with sync_playwright() as p:
        browser = _launch(p, _pw_proxy(proxy) if mode == "live" else None)
        try:
            ctx = browser.new_context(java_script_enabled=False, viewport=VIEWPORT, user_agent=ua,
                                      locale="es-ES", accept_downloads=False, ignore_https_errors=not strict,
                                      service_workers="block")
            page = ctx.new_page()
            if mode == "offline":
                page.route("**/*", lambda route: route.abort())
                page.set_content(Path(target).read_text(encoding="utf-8", errors="replace"), wait_until="domcontentloaded",
                                 timeout=30000)
            else:
                resp = page.goto(target, wait_until="load", timeout=GOTO_TIMEOUT_MS)
                res["status"] = resp.status if resp else None
                res["final_url"] = page.url
            page.screenshot(path=out, full_page=True, timeout=30000)
            res["ok"] = True
        except Exception as exc:  # noqa: BLE001
            res["error"] = f"{exc.__class__.__name__}: {str(exc)[:300]}"
        finally:
            browser.close()
    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
