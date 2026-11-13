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
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]

# page → [(sample in samples.zip, [(tab, picture name, 'first|last' element of the picture or None), …]), …]
# tab: a Components sub-tab id, or "@c2" / "@ml" / "@yara" / "@hex" / "@reports" for an engine view
# (the module is run on the case first). None = the tab and its pane (or the engine's panel).
SHOTS: dict[str, list[tuple[str, list[tuple[str, str, str | None]]]]] = {
    "email": [
        ("email/sample.eml", [
            ("verdict", "verdict", None),
            ("auth", "authentication", None),
            ("headers", "headers", None),
            ("attachments", "attachments", None),
            ("body", "body", None),
            ("findings", "findings", None),
            ("iocs", "iocs", None),
            ("findings", "delivery-path", "#comp-case|.nested-panel"),
        ]),
        ("email/sample_email_chain.eml", [("chain", "chain", None)]),
        ("email/sample_m365_headers.eml", [("auth", "m365-authentication", None)]),
        ("email/sample_brand_lookalike.eml", [("lookalikes", "lookalikes", None)]),
        ("email/sample_gateway_links.eml", [("iocs", "iocs-gateway-links", None)]),
    ],
    "office": [
        ("word/sample.docm", [("vba", "vba", None), ("content", "content", None), ("metadata", "metadata", None),
                              ("tools", "tools", None), ("relationships", "relationships", None)]),
        ("excel/sample.xlsm", [("content", "excel-content", None)]),
    ],
    "rtf": [("word/sample.rtf", [("rtfobjects", "objects", None), ("rtfstructure", "structure", None),
                                 ("rtftext", "text", None), ("rtfmeta", "metadata", None)])],
    "pdf": [("pdf/sample.pdf", [("pdf", "pdf", None), ("pdftools", "pdftools", None), ("embedded", "embedded", None),
                                ("javascript", "javascript", None)])],
    "onenote": [("onenote/sample_notes.one", [("onenote", "onenote", None)])],
    "registry": [("registry/sample_persistence.reg", [("registry", "findings", None), ("registry", "sql", None)]),
                 ("registry/sample_NTUSER.DAT", [("registry", "browse", None), ("registry", "search", None),
                                                 ("registry", "artifacts", None), ("registry", "timeline", None)])],
    "shortcuts": [("shortcuts/sample_shortcut.pdf.lnk", [("shortcut", "shortcut", None)])],
    "scripts": [
        ("javascript/sample_obf_techniques.js", [("javascript", "javascript", None)]),
        ("powershell/sample_crypto_loader.ps1", [("powershell", "powershell", None)]),
        ("vbscript/sample_xor_loader.vbs", [("vbscript", "vbscript", None)]),
        ("batch/sample_dosfuscation.bat", [("batch", "batch", None)]),
        ("python/sample_dropper.pyc", [("python", "python", None)]),
    ],
    "java": [("java/sample_app.jar", [("java", "java", None)])],
    "installers": [("installers/sample_installer.msi", [("msi", "msi", None)])],
    "windows-pe": [
        ("windows-pe/sample_packed.exe", [("msi", "binary", None)]),
        ("windows-pe/sample_code_loader.exe", [("code", "code", None)]),
        ("windows-pe/sample_pyinstaller.exe", [("pyinstaller", "pyinstaller", None)]),
    ],
    "dotnet": [
        ("dotnet/sample_dotnet_loader.exe", [("dotnet", "dotnet", None)]),
        ("dotnet/sample_dotnet_crypter_chain.exe", [("dotnet", "stages", ".nested-panel")]),
    ],
    "go": [("go/sample_go_code.exe", [("golang", "go", None)])],
    "other-binaries": [("linux-elf/sample_elf_backdoor", [("msi", "elf", None), ("code", "elf-code", None)])],
    "archives": [
        ("archives/dropper_bundle.zip", [("archive", "archive", None), ("archive", "nested", ".nested-panel")]),
        ("disk-images/sample_image.iso", [("archive", "iso", ".nested-panel")]),
    ],
    "images": [
        ("images/sample_logo_appended.png", [("findings", "appended", ".nested-panel")]),
        ("archives/sample_stego_invoice.zip", [("findings", "pixels", ".nested-panel")]),
    ],
    "memdump": [("memdump/sample_memdump_factura.dmp", [("memdump", "memdump", None),
                                                          ("memdump", "carved", ".nested-panel")])],
    "c2": [
        ("c2/cobaltstrike/sample_cs_beacon.bin", [("@c2", "cobaltstrike", None)]),
        ("c2/asyncrat/sample_asyncrat.exe", [("@c2", "asyncrat", None)]),
    ],
    "ml": [("dotnet/sample_dotnet_stealer_ml.exe", [("@ml", "ml", None)])],
    "yara": [("email/sample.eml", [("@yara", "yara", None)])],
    "hex": [("windows-pe/sample_win32_invoice_calc.dll", [("@hex", "hex", None)])],
    "reports": [("email/sample.eml", [("@reports", "report", None)])],
    # no sample: the Users view (signed in as admin; first-start.webp is taken before signing in)
    "access": [(None, [("@users", "users", None)])],
    # no sample: the Settings view, filled with invented example values (not saved)
    "configuration": [(None, [("@settings", "proxy", "#settings-status|#free-status"),
                              ("@settings", "organisation", "#allowed-countries-msg|#email-msg")])],
}

# inner tab to open before the picture, by (page, picture)
_CLICKS = {("windows-pe", "binary"): '[data-itab="pefile"]', ("other-binaries", "elf"): '[data-itab="lief"]',
           ("registry", "browse"): ['[data-itab="browse"]', r"@fill:#reg-b-path=HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                                     "#reg-b-go"],
           ("registry", "search"): ['[data-itab="search"]', "@fill:#reg-s-q=mshta", "#reg-s-go"],
           ("registry", "sql"): ['[data-itab="sql"]', "#reg-q-go"],
           ("registry", "artifacts"): ['[data-itab="artifacts"]', '[data-reg-art-plugin="user_assist"]'],
           ("registry", "timeline"): ['[data-itab="timeline"]']}

# a YARA rule for the YARA page (inert: it matches the campaign's own indicators)
_YARA_RULE = b"""rule Invoice_Fraud_Campaign_Indicators
{
    meta:
        description = "Indicators of the invoice-fraud campaign of the DocuTraceX samples"
    strings:
        $d1 = "cdn-update.example.net" ascii wide nocase
        $d2 = "rnicrosoft-online.example" ascii wide nocase
        $ip = "203.0.113.47" ascii wide
    condition:
        any of them
}
"""

# how each engine view is opened in the page, and which module it needs first
_ENGINE_JS = {
    "@c2": "async (id) => { showTab('c2'); _c2Case = id; await loadC2View(id); }",
    "@ml": "async (id) => { showTab('ml'); _mlCase = id; await loadMlView(id); }",
    "@yara": "async (id) => { showTab('yara'); await loadYara(); const s = document.getElementById('yara-case');"
             " await fillCaseSelect(s, id); s.value = id; await showYaraResults(id); }",
    "@hex": "async (id) => { showTab('hex'); await loadHexView(); await fillCaseSelect(document.getElementById('hex-case'), id);"
            " hexResetCase(id); renderHexView(); }",
    "@reports": "async (id) => { _openCaseId = id; showTab('reports'); loadReports(id); }",
    "@settings": "async () => { showTab('settings'); loadSettings(); }",
    "@users": "async () => { showTab('users'); await loadUsersView(); }",
}

# run after the view has loaded: example values for the pictures (never saved)
_AFTER_JS = {
    "@settings": "() => { const set = (i, v) => { const e = document.getElementById(i); if (e) e.value = v; };"
                 " document.getElementById('proxy-enabled').checked = true; set('proxy-scheme', 'socks5');"
                 " set('proxy-host', '127.0.0.1'); set('proxy-port', '9050');"
                 " set('email-own', ['grupoejemplo.example', 'grupoejemplo-servicios.example',"
                 " 'proveedor-iberia.example'].join(String.fromCharCode(10)));"
                 " set('email-brands', ['grupoejemplo', 'suministros-iberia'].join(String.fromCharCode(10)));"
                 " [['sim-short-len', 4], ['sim-short-dist', 1], ['sim-long-len', 9], ['sim-long-dist', 2],"
                 " ['sim-xlong-dist', 3], ['sim-min-len', 4]].forEach(([i, v]) => {"
                 " const e = document.getElementById(i); if (e && e.value === '') e.value = v; }); }",
}
_ENGINE_MODULE = {"@c2": "c2", "@ml": "ml", "@yara": "yara"}

WIDTH, HEIGHT = 1440, 900
MAX_H = 1000                 # css px: long panes are cut here


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _analyse(samples: list[str], cases: Path, modules: dict[str, set[str]]) -> dict[str, str]:
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
        for mod in sorted(modules.get(name, ())):
            print(f"  running {mod} on {name} …", flush=True)
            analyze.run_module(cases / m["analysis_id"], mod)
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


_ADMIN_PW = "docs-screenshots-only"


def _sign_in(page, base: str, first_start_shot: bool) -> None:
    """The app is behind a sign-in: take the first-start screen if asked, set the
    admin password of this throw-away installation, add two example users and
    a few audited actions for the Users page."""
    hdr = {"X-DTX": "1"}
    if first_start_shot:
        (OUT / "access").mkdir(parents=True, exist_ok=True)
        page.goto(base + "/login")
        page.wait_for_load_state("networkidle")
        page.fill("#pw1", _ADMIN_PW)
        page.fill("#pw2", _ADMIN_PW)
        _webp(page.locator(".login-card").screenshot(), OUT / "access" / "first-start.webp")
        print(f"  {(OUT / 'access' / 'first-start.webp').relative_to(ROOT)}")
    page.request.post(base + "/api/auth/setup", data={"password": _ADMIN_PW}, headers=hdr)
    for name in ("analista.uno", "analista.dos"):
        page.request.post(base + "/api/users", data={"username": name, "password": "example-pass-1"}, headers=hdr)
    page.request.put(base + "/api/settings/email", headers=hdr,
                     data={"own_domains": ["grupoejemplo.example"], "brands": ["grupoejemplo"]})


def _shoot(base: str, ids: dict[str, str], pages: list[str], scale: int) -> None:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for theme in ("dark",):                                   # the app has one (dark) theme
            ctx = browser.new_context(viewport={"width": WIDTH, "height": HEIGHT}, device_scale_factor=scale,
                                      color_scheme=theme)
            page = ctx.new_page()
            _sign_in(page, base, "access" in pages)
            page.goto(base + "/")
            page.wait_for_load_state("networkidle")
            for pg in pages:
                (OUT / pg).mkdir(parents=True, exist_ok=True)
                for sample, tabs in SHOTS[pg]:
                    for tab, pic, focus in tabs:
                        if tab.startswith("@"):
                            page.evaluate(_ENGINE_JS[tab], ids.get(sample))
                            host, default = ".view:not([hidden]) .panel", ".view:not([hidden]) .panel"
                        else:
                            page.evaluate("([id, tab]) => openComponents(id, tab)", [ids[sample], tab])
                            host, default = "#comp-body", "#comp-body .subtabs|#comp-body .subpane"
                        page.wait_for_load_state("networkidle")
                        page.wait_for_timeout(1500 if tab.startswith("@") else 700)
                        if tab in _AFTER_JS:
                            page.wait_for_timeout(2500)
                            page.evaluate(_AFTER_JS[tab])
                            page.wait_for_timeout(200)
                        if (pg, pic) in _CLICKS:
                            steps = _CLICKS[(pg, pic)]
                            for sel in [steps] if isinstance(steps, str) else steps:
                                if sel.startswith("@fill:"):
                                    target, _, text = sel[6:].partition("=")
                                    page.fill(target, text)
                                else:
                                    page.locator(sel).first.click()
                                page.wait_for_timeout(700)
                        # crop to the tab bar + its pane (or to the element asked for), at most MAX_H tall
                        box = page.evaluate(
                            "([sel, host]) => { const [s1, s2] = sel.split('|');"
                            " const top = document.querySelector(s1), end = s2 ? document.querySelector(s2) : top;"
                            " const a = top.getBoundingClientRect(), b = end.getBoundingClientRect();"
                            " const h = document.querySelector(host).getBoundingClientRect();"
                            " return {x: h.left - 8, y: a.top + window.scrollY - 12,"
                            " w: h.width + 16, h: b.bottom - a.top + 24}; }", [focus or default, host])
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
    tmp_cfg = tempfile.mkdtemp(prefix="dtx-docshots-config-")
    os.environ["DOCUTRACEX_CONFIG_DIR"] = tmp_cfg             # users, sessions, audit: throw-away
    with tempfile.TemporaryDirectory(prefix="dtx-docshots-") as tmp:
        cases = Path(tmp) / "cases"
        cases.mkdir()
        from docutracex import yara_engine
        from docutracex.config import settings
        settings.yara_dir = Path(tmp) / "yara"
        yara_engine.add_upload("invoice_campaign.yar", _YARA_RULE)
        list(yara_engine.compile_stream())                      # compile (and cache) the ruleset
        samples = sorted({s for pg in pages for s, _ in SHOTS[pg] if s})
        modules: dict[str, set[str]] = {}
        for pg in pages:
            for smp, tabs in SHOTS[pg]:
                for tab, _pic, _f in tabs:
                    if tab in _ENGINE_MODULE:
                        modules.setdefault(smp, set()).add(_ENGINE_MODULE[tab])
        ids = _analyse(samples, cases, modules)
        with _serve(_free_port()) as base:
            _shoot(base, ids, pages, a.scale)


if __name__ == "__main__":
    main()
