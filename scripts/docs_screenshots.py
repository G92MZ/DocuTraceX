"""Screenshots for the documentation site (``docs/``), taken from the **inert
samples** in ``samples/samples.zip`` — never from a real case, so no evidence
ever reaches the docs.

    python scripts/docs_screenshots.py                 # every page
    python scripts/docs_screenshots.py --only email    # one page
    python scripts/docs_screenshots.py --list          # what it would take

It analyses each sample into a throw-away cases folder (the same pipeline as
the app; network lookups off), serves the app on a free local port, opens each
case's tab in headless Chromium and writes ``docs/assets/shots/<page>/<name>.webp``.
Re-run it when the interface changes.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets" / "shots"

# page → [(sample in samples.zip, [(tab id, picture name, 'first|last' element of the picture or None = the tab and its pane), …]), …]
SHOTS: dict[str, list[tuple[str, list[tuple[str, str, str | None]]]]] = {
    "email": [
        ("email/sample.eml", [
            ("verdict", "verdict", None),
            ("auth", "authentication", None),
            ("headers", "headers", None),
            ("attachments", "attachments", None),
            ("body", "body", None),
            ("findings", "findings", None),
            ("findings", "delivery-path", "#comp-case|.nested-panel"),
        ]),
        ("email/sample_email_chain.eml", [("chain", "chain", None)]),
        ("email/sample_m365_headers.eml", [("auth", "m365-authentication", None)]),
        ("email/sample_brand_lookalike.eml", [("lookalikes", "lookalikes", None)]),
        ("email/sample_gateway_links.eml", [("iocs", "iocs-gateway-links", None)]),
    ],
}

WIDTH, HEIGHT = 1440, 900
MAX_H = 1000                 # css px: long panes are cut here


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _analyse(samples: list[str], cases: Path) -> dict[str, str]:
    sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
    import zipcrypto

    from docutracex import analyze, cases as case_service
    from docutracex.config import settings

    settings.cases_dir = cases
    out: dict[str, str] = {}
    for name in samples:
        data = zipcrypto.read(ROOT / "samples" / "samples.zip", name)
        import io
        m = case_service.create_case(io.BytesIO(data), Path(name).name, cases_dir=cases)
        print(f"  analysing {name} …", flush=True)
        analyze.analyze_case(cases / m["analysis_id"])
        out[name] = m["analysis_id"]
    return out


@contextlib.contextmanager
def _serve(port: int):
    import uvicorn

    from docutracex.app import create_app
    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        th.join(timeout=10)


def _webp(png: bytes, path: Path) -> None:
    """WebP keeps the text sharp at a fraction of the PNG size (the repo ships them)."""
    import io

    from PIL import Image
    Image.open(io.BytesIO(png)).convert("RGB").save(path, "WEBP", quality=80, method=6)


def _shoot(base: str, ids: dict[str, str], pages: list[str], scale: int) -> None:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for theme in ("dark",):                                   # the app has one (dark) theme
            ctx = browser.new_context(viewport={"width": WIDTH, "height": HEIGHT}, device_scale_factor=scale,
                                      color_scheme=theme)
            page = ctx.new_page()
            page.goto(base + "/")
            page.wait_for_load_state("networkidle")
            for pg in pages:
                (OUT / pg).mkdir(parents=True, exist_ok=True)
                for sample, tabs in SHOTS[pg]:
                    for tab, pic, focus in tabs:
                        page.evaluate("([id, tab]) => openComponents(id, tab)", [ids[sample], tab])
                        page.wait_for_load_state("networkidle")
                        page.wait_for_timeout(700)
                        # crop to the tab bar + its pane (or to the element asked for), at most MAX_H tall
                        box = page.evaluate(
                            "(sel) => { const [s1, s2] = (sel || '#comp-body .subtabs|#comp-body .subpane').split('|');"
                            " const top = document.querySelector(s1), end = s2 ? document.querySelector(s2) : top;"
                            " const a = top.getBoundingClientRect(), b = end.getBoundingClientRect();"
                            " const host = document.querySelector('#comp-body').getBoundingClientRect();"
                            " return {x: host.left - 8, y: a.top + window.scrollY - 12,"
                            " w: host.width + 16, h: b.bottom - a.top + 24}; }", focus)
                        clip = {"x": max(0, box["x"]), "y": max(0, box["y"]), "width": box["w"],
                                "height": min(MAX_H, box["h"])}
                        path = OUT / pg / f"{pic}.webp"
                        _webp(page.screenshot(clip=clip, full_page=True), path)
                        print(f"  {path.relative_to(ROOT)}")
            ctx.close()
        browser.close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", action="append", choices=sorted(SHOTS), help="page(s) to take (default: all)")
    ap.add_argument("--scale", type=int, default=2, help="device scale factor (default 2: sharp on hi-dpi)")
    ap.add_argument("--list", action="store_true", help="print the pictures and exit")
    a = ap.parse_args()
    pages = a.only or sorted(SHOTS)
    if a.list:
        for pg in pages:
            for sample, tabs in SHOTS[pg]:
                for tab, pic, _ in tabs:
                    print(f"{pg}/{pic}.webp  ←  {sample} › {tab}")
        return
    os.environ.setdefault("DOCUTRACEX_TENANT_LOOKUP", "0")      # no lookups: the docs show only the sample
    os.environ.setdefault("DOCUTRACEX_OFFLINE", "1")
    with tempfile.TemporaryDirectory(prefix="dtx-docshots-") as tmp:
        cases = Path(tmp) / "cases"
        cases.mkdir()
        samples = sorted({s for pg in pages for s, _ in SHOTS[pg]})
        ids = _analyse(samples, cases)
        with _serve(_free_port()) as base:
            _shoot(base, ids, pages, a.scale)


if __name__ == "__main__":
    main()
