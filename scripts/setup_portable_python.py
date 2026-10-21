#!/usr/bin/env python3
"""Provision the portable Python runtime under ``tools/`` and its dependencies.

Downloads a python-build-standalone CPython build (Astral) for this platform,
extracts it to ``tools/python/``, installs the app and its dependencies into it
(so DocuTraceX runs on the bundled interpreter), and on Windows also provisions
the native libmagic (DLL + magic database) under ``tools/libmagic/``.

Primary version: CPython 3.13 (broadest wheel coverage today). A second,
separate interpreter — PyPy 2.7 under ``tools/pypy/`` — is provisioned only for
ViperMonkey (VBA emulation), whose code is Python 2 only.

Usage:
    python scripts/setup_portable_python.py            # 3.13, this platform
    python scripts/setup_portable_python.py --version 3.12
    python scripts/setup_portable_python.py --libmagic-only   # just the Windows DLL

Note: downloads from GitHub (python-build-standalone) and PyPI. Run it on the
target machine (e.g. Windows) where those are reachable.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
PY_DIR = TOOLS / "python"
LIBMAGIC_DIR = TOOLS / "libmagic"
DIDIER_DIR = TOOLS / "didier"
OMS_DIR = TOOLS / "officemalscanner"

DIDIER_BASE = "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/"
DIDIER_FILES = [
    "oledump.py", "zipdump.py", "pdfid.py", "pdf-parser.py", "emldump.py", "rtfdump.py",
    "decode-vbe.py",  # decodes Script Encoder (.jse/.vbe) payloads
    # oledump plugins (loaded with -p): BIFF/XLM records, VBA summary/DCO/routines,
    # HTTP-looking strings and generic stream object heuristics.
    "plugin_biff.py", "plugin_vba_summary.py", "plugin_vba_dco.py",
    "plugin_vba_routines.py", "plugin_http_heuristics.py", "plugin_stream_o.py",
]

# Second portable interpreter: PyPy 2.7, used only by ViperMonkey (VBA emulation),
# whose code is Python 2 only. Official builds from pypy.org (MIT).
PYPY_DIR = TOOLS / "pypy"
PYPY_VERSION = "7.3.17"
PYPY_BASE = "https://downloads.python.org/pypy/"
# ViperMonkey (BSD-like, P. Lagadec / K. Sayre), pinned to a known-good commit.
VIPERMONKEY_COMMIT = "73547cef7f82dbcb10e22e36b84b558a07f7d21d"
VIPERMONKEY_URLS = (
    f"https://github.com/decalage2/ViperMonkey/archive/{VIPERMONKEY_COMMIT}.zip",
    f"https://codeload.github.com/decalage2/ViperMonkey/zip/{VIPERMONKEY_COMMIT}",
)
# Its requirements, minus ``regex`` (needs a C compiler under PyPy and is optional)
# and ``psutil`` (only used to drive LibreOffice for Excel exports).
VIPERMONKEY_DEPS = ["oletools>=0.56.1,<=0.60.2", "olefile", "prettytable", "colorlog",
                    "colorama", "pyparsing==2.2.0", "xlrd2", "xlrd", "unidecode==1.2.0"]

# OfficeMalScanner (Frank Boldewin), freeware. The original site
# (reconstructer.org) is offline; the author republished it on his GitHub, which
# is tried first. Windows PE binaries, downloaded at provision time, never
# redistributed here.
OMS_URLS = (
    "https://raw.githubusercontent.com/fboldewin/reconstructer.org/master/OfficeMalScanner.zip",
    "http://www.reconstructer.org/code/OfficeMalScanner.zip",
)
OMS_EXE = "OfficeMalScanner.exe"

PBS_API = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest"
DEFAULT_VERSION = "3.13"


def _arch() -> str:
    m = platform.machine().lower()
    if m in ("amd64", "x86_64", "x64"):
        return "x86_64"
    if m in ("arm64", "aarch64"):
        return "aarch64"
    raise SystemExit(f"Unsupported architecture: {platform.machine()}")


def _asset_suffix() -> str:
    arch = _arch()
    if sys.platform.startswith("win"):
        return f"{arch}-pc-windows-msvc-install_only.tar.gz"
    if sys.platform == "darwin":
        return f"{arch}-apple-darwin-install_only.tar.gz"
    # iOA1JtNL0m
    return f"{arch}-unknown-linux-gnu-install_only.tar.gz"


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "DocuTraceX-setup"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def _find_asset(version: str) -> tuple[str, str]:
    """Return (asset_name, download_url) for the best matching build."""
    data = json.loads(_get(PBS_API))
    suffix = _asset_suffix()
    prefix = f"cpython-{version}."
    best = None
    for asset in data.get("assets", []):
        name = asset["name"]
        if name.startswith(prefix) and name.endswith(suffix):
            # sort key: the patch number after "cpython-3.13."
            try:
                patch = int(name[len(prefix):].split("+", 1)[0].split("-", 1)[0])
            except ValueError:
                patch = -1
            if best is None or patch > best[0]:
                best = (patch, name, asset["browser_download_url"])
    if best is None:
        raise SystemExit(
            f"No python-build-standalone asset for {version} / {suffix} in the "
            f"latest release. Check https://github.com/astral-sh/python-build-standalone/releases"
        )
    return best[1], best[2]


def _portable_python() -> Path:
    for c in (PY_DIR / "python.exe", PY_DIR / "bin" / "python3", PY_DIR / "bin" / "python"):
        if c.is_file():
            return c
    raise SystemExit(f"Could not find the portable interpreter under {PY_DIR}")


def _portable_present() -> bool:
    for c in (PY_DIR / "python.exe", PY_DIR / "bin" / "python3", PY_DIR / "bin" / "python"):
        if c.is_file():
            return True
    return False


def install_python(version: str, force: bool) -> None:
    if PY_DIR.exists():
        if not force:
            print(f"[=] {PY_DIR} already exists (use --force to reinstall). Skipping download.")
            return
        shutil.rmtree(PY_DIR)

    name, url = _find_asset(version)
    print(f"[>] Downloading {name}")
    TOOLS.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp.write(_get(url))
        archive = Path(tmp.name)
    print("[>] Extracting to tools/python/")
    with tarfile.open(archive, "r:gz") as tar:
        # python-build-standalone extracts to a top-level "python/" directory.
        try:
            tar.extractall(TOOLS, filter="data")  # Python 3.12+
        except TypeError:
            tar.extractall(TOOLS)
    archive.unlink(missing_ok=True)
    print(f"[+] Portable Python at {_portable_python()}")


def install_deps() -> None:
    py = _portable_python()
    print("[>] Upgrading pip in the portable interpreter")
    subprocess.run([str(py), "-m", "pip", "install", "--upgrade", "pip"], check=False)
    print("[>] Installing DocuTraceX + the analysis toolchain into the portable interpreter")
    # The [tools] extra carries every analysis dependency (oletools, YARA,
    # STPyV8, Playwright, pikepdf, …) — they land ONLY on the portable, never on
    # the user's Python. The web service deps come along as base requirements.
    subprocess.run([str(py), "-m", "pip", "install", "-e", f"{ROOT}[tools]"], check=True)


def install_libmagic_windows() -> None:
    """Extract libmagic.dll + magic.mgc from the python-magic-bin wheel (PyPI)."""
    print("[>] Provisioning native libmagic (Windows) into tools/libmagic/")
    with tempfile.TemporaryDirectory() as td:
        rc = subprocess.run(
            [sys.executable, "-m", "pip", "download", "python-magic-bin",
             "--only-binary", ":all:", "--platform", "win_amd64", "--no-deps", "-d", td],
            check=False,
        )
        if rc.returncode != 0:
            print("[!] Could not download python-magic-bin wheel; skipping libmagic.")
            return
        wheels = list(Path(td).glob("*.whl"))
        if not wheels:
            print("[!] No wheel downloaded; skipping libmagic.")
            return
        LIBMAGIC_DIR.mkdir(parents=True, exist_ok=True)
        extracted = []
        with zipfile.ZipFile(wheels[0]) as z:
            for member in z.namelist():
                low = member.lower()
                if low.endswith(("libmagic.dll", "magic1.dll", "magic.mgc")) or \
                        (low.endswith(".dll") and "libmagic" in low):
                    target = LIBMAGIC_DIR / Path(member).name
                    with z.open(member) as src, target.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                    extracted.append(target.name)
        print(f"[+] libmagic files: {', '.join(extracted) or 'none'} -> {LIBMAGIC_DIR}")


def install_didier() -> None:
    """Download the Didier Stevens Suite scripts into tools/didier/ (public domain)."""
    print("[>] Provisioning Didier Stevens Suite scripts into tools/didier/")
    DIDIER_DIR.mkdir(parents=True, exist_ok=True)
    got = []
    for name in DIDIER_FILES:
        try:
            data = _get(DIDIER_BASE + name)
            (DIDIER_DIR / name).write_bytes(data)
            got.append(name)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Could not download {name}: {exc}")
    print(f"[+] Didier scripts: {', '.join(got) or 'none'}")


def _didier_present() -> bool:
    return all((DIDIER_DIR / f).is_file() for f in DIDIER_FILES)


def install_officemalscanner() -> None:
    """Download and extract the OfficeMalScanner suite into tools/officemalscanner/.

    Best-effort: if every source fails, or the EXE is quarantined by AV, it
    prints a note and the module simply degrades (checked by presence, like the
    Didier scripts). Drop the files there manually if the download fails.
    """
    print("[>] Provisioning OfficeMalScanner into tools/officemalscanner/")
    data = None
    for url in OMS_URLS:
        try:
            data = _get(url)
            break
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Could not download OfficeMalScanner from {url} ({exc}).")
    if data is None:
        print(f"    Drop {OMS_EXE} (and its DLLs) into {OMS_DIR} manually "
              "(https://github.com/fboldewin/reconstructer.org).")
        return
    OMS_DIR.mkdir(parents=True, exist_ok=True)
    got: list[str] = []
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for member in z.namelist():
                # The EXEs need the bundled DLLs (Unzipper, LZNT1Decompress, ...).
                if member.lower().endswith((".exe", ".dll")):
                    target = OMS_DIR / Path(member).name
                    with z.open(member) as src, target.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                    got.append(target.name)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not extract OfficeMalScanner zip: {exc}")
        return
    print(f"[+] OfficeMalScanner files: {', '.join(got) or 'none'} -> {OMS_DIR}")
    if OMS_EXE not in got:
        print(f"[!] {OMS_EXE} not found in the archive; the module will stay disabled.")


def _officemalscanner_present() -> bool:
    return (OMS_DIR / OMS_EXE).is_file()


# --- PyPy 2.7 + ViperMonkey -------------------------------------------------------

def _pypy_asset() -> str:
    arch = _arch()
    if sys.platform.startswith("win"):
        return f"pypy2.7-v{PYPY_VERSION}-win64.zip"
    if sys.platform == "darwin":
        return f"pypy2.7-v{PYPY_VERSION}-macos_{'arm64' if arch == 'aarch64' else 'x86_64'}.tar.bz2"
    return f"pypy2.7-v{PYPY_VERSION}-{'aarch64' if arch == 'aarch64' else 'linux64'}.tar.bz2"


def pypy_executable() -> Path | None:
    for c in (PYPY_DIR / "pypy.exe", PYPY_DIR / "bin" / "pypy", PYPY_DIR / "bin" / "pypy2"):
        if c.is_file():
            return c
    return None


def install_pypy() -> bool:
    """Download PyPy 2.7 into tools/pypy/ (flattening its top-level folder)."""
    if pypy_executable():
        return True
    name = _pypy_asset()
    print(f"[>] Provisioning PyPy 2.7 (for ViperMonkey) into tools/pypy/: {name}")
    try:
        data = _get(PYPY_BASE + name)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download PyPy ({exc}); ViperMonkey stays disabled.")
        return False
    import io
    # AeWckx3pKh
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        try:
            if name.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    z.extractall(tdp)
            else:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:bz2") as t:
                    try:
                        t.extractall(tdp, filter="tar")  # keeps the bin/ symlinks
                    except TypeError:
                        t.extractall(tdp)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Could not extract PyPy: {exc}")
            return False
        tops = [p for p in tdp.iterdir() if p.is_dir()]
        if len(tops) != 1:
            print("[!] Unexpected PyPy archive layout.")
            return False
        if PYPY_DIR.exists():
            shutil.rmtree(PYPY_DIR)
        shutil.move(str(tops[0]), str(PYPY_DIR))
    exe = pypy_executable()
    if exe is None:
        print("[!] PyPy extracted but its executable was not found.")
        return False
    subprocess.run([str(exe), "-m", "ensurepip"], check=False, capture_output=True)
    print(f"[+] PyPy at {exe}")
    return True


def _vipermonkey_ok() -> bool:
    exe = pypy_executable()
    if exe is None:
        return False
    try:
        r = subprocess.run([str(exe), "-c", "import vipermonkey.vmonkey"],
                           capture_output=True, timeout=120)
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def install_vipermonkey(source: str | None = None) -> bool:
    """Install ViperMonkey (pinned) and its Python 2 dependencies into PyPy.

    ``source`` (or env DOCUTRACEX_VIPERMONKEY_SRC) may point to a local checkout
    or archive instead of the GitHub download.
    """
    import os

    # tag: gmzpt
    exe = pypy_executable()
    if exe is None and not install_pypy():
        return False
    exe = pypy_executable()
    pip = [str(exe), "-m", "pip", "--disable-pip-version-check", "-q"]
    print("[>] Installing ViperMonkey into PyPy (Python 2.7)")
    r = subprocess.run(pip + ["install", *VIPERMONKEY_DEPS], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[!] ViperMonkey dependencies failed: {r.stderr.strip()[-400:]}")
        return False
    sources = [source or os.environ.get("DOCUTRACEX_VIPERMONKEY_SRC") or ""]
    sources = [x for x in sources if x] or list(VIPERMONKEY_URLS)
    for src in sources:
        r = subprocess.run(pip + ["install", "--no-deps", src], capture_output=True, text=True)
        if r.returncode == 0 and _vipermonkey_ok():
            print("[+] ViperMonkey installed")
            return True
        print(f"[!] Could not install ViperMonkey from {src}: {r.stderr.strip()[-300:]}")
    return False


IPDB_DIR = TOOLS / "ipdb"
PLAYWRIGHT_DIR = TOOLS / "playwright"
DBIP_BASE = "https://download.db-ip.com/free/"
IP2ASN_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"


def _month_candidates() -> list[str]:
    import datetime as _dt
    today = _dt.date.today()
    prev = (today.replace(day=1) - _dt.timedelta(days=1))
    return [today.strftime("%Y-%m"), prev.strftime("%Y-%m")]


def install_ipdb(force: bool = False) -> bool:
    """DB-IP Lite (ASN + country, CC BY 4.0) and iptoasn (public domain) into
    tools/ipdb/. Refreshed when older than ~35 days."""
    import gzip
    import time as _time

    IPDB_DIR.mkdir(parents=True, exist_ok=True)
    ok = True
    for kind in ("asn", "country"):
        dest = IPDB_DIR / f"dbip-{kind}-lite.mmdb"
        if dest.is_file() and not force and _time.time() - dest.stat().st_mtime < 35 * 86400:
            continue
        got = False
        for month in _month_candidates():
            url = f"{DBIP_BASE}dbip-{kind}-lite-{month}.mmdb.gz"
            try:
                print(f"[>] Downloading DB-IP Lite {kind} ({month})")
                dest.write_bytes(gzip.decompress(_get(url)))
                got = True
                break
            except Exception as exc:  # noqa: BLE001
                print(f"[!] {url}: {exc}")
        ok = ok and got
    dest = IPDB_DIR / "ip2asn-combined.tsv.gz"
    if force or not dest.is_file() or _time.time() - dest.stat().st_mtime > 35 * 86400:
        try:
            print("[>] Downloading iptoasn ip2asn-combined")
            dest.write_bytes(_get(IP2ASN_URL))
        except Exception as exc:  # noqa: BLE001
            print(f"[!] iptoasn: {exc}")
    return ok


def _ipdb_ok() -> bool:
    return all((IPDB_DIR / f"dbip-{k}-lite.mmdb").is_file() for k in ("asn", "country"))


def install_chromium() -> bool:
    """Headless Chromium for Playwright (screenshots) into tools/playwright/."""
    import os

    py = _portable_python()
    env = dict(os.environ, PLAYWRIGHT_BROWSERS_PATH=str(PLAYWRIGHT_DIR))
    print("[>] Installing Chromium for Playwright into tools/playwright/")
    r = subprocess.run([str(py), "-m", "playwright", "install", "chromium"], env=env, check=False)
    return r.returncode == 0 and _chromium_ok()


def _chromium_ok() -> bool:
    return PLAYWRIGHT_DIR.is_dir() and any(PLAYWRIGHT_DIR.glob("chromium*"))


# --- Node.js + webcrack (JS deobfuscation) ----------------------------------
NODE_DIR = TOOLS / "node"
NODE_VERSION = "22.11.0"                       # LTS; MIT
NODE_BASE = "https://nodejs.org/dist/"
WEBCRACK_DIR = TOOLS / "webcrack"
WEBCRACK_VERSION = "2.16.0"                     # MIT


def _node_asset() -> tuple[str, str]:
    arch = "x64" if _arch() == "x86_64" else "arm64"
    v = NODE_VERSION
    if sys.platform.startswith("win"):
        name = f"node-v{v}-win-{arch}.zip"
    elif sys.platform == "darwin":
        name = f"node-v{v}-darwin-{arch}.tar.gz"
    else:
        name = f"node-v{v}-linux-{arch}.tar.xz"
    return name, f"{NODE_BASE}v{v}/{name}"


def node_executable() -> Path | None:
    for c in (NODE_DIR / "node.exe", NODE_DIR / "bin" / "node", NODE_DIR / "node"):
        if c.is_file():
            return c
    for p in sorted(NODE_DIR.glob("node*/bin/node")) + sorted(NODE_DIR.glob("node*/node.exe")):
        if p.is_file():
            return p
    return None


def _npm_cmd(node: Path) -> list[str]:
    base = node.parent
    cli = base / "node_modules" / "npm" / "bin" / "npm-cli.js"
    if not cli.is_file():
        cli = NODE_DIR / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"
    if cli.is_file():
        return [str(node), str(cli)]
    return [str(base / ("npm.cmd" if sys.platform.startswith("win") else "npm"))]


def install_node() -> bool:
    """Portable Node.js into tools/node/ (flattening its top-level folder)."""
    if node_executable():
        return True
    name, url = _node_asset()
    print(f"[>] Provisioning portable Node.js (for webcrack) into tools/node/: {name}")
    try:
        data = _get(url)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download Node ({exc}); webcrack stays disabled.")
        return False
    import io
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        try:
            if name.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    z.extractall(tdp)
            else:
                mode = "r:xz" if name.endswith(".xz") else "r:gz"
                with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as t:
                    try:
                        t.extractall(tdp, filter="tar")
                    except TypeError:
                        t.extractall(tdp)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Could not extract Node: {exc}")
            return False
        tops = [p for p in tdp.iterdir() if p.is_dir()]
        if len(tops) != 1:
            print("[!] Unexpected Node archive layout.")
            return False
        if NODE_DIR.exists():
            shutil.rmtree(NODE_DIR)
        shutil.move(str(tops[0]), str(NODE_DIR))
    exe = node_executable()
    if exe is None:
        print("[!] Node extracted but its executable was not found.")
        return False
    print(f"[+] Node at {exe}")
    return True


def _webcrack_ok() -> bool:
    return (WEBCRACK_DIR / "node_modules" / "webcrack").is_dir()


def install_webcrack() -> bool:
    """npm-install webcrack (MIT) into tools/webcrack/. It pulls isolated-vm,
    which builds from source — needs Node build tools on the host; on failure
    webcrack stays disabled and the pure-Python JS cascade is the fallback."""
    if _webcrack_ok():
        return True
    node = node_executable()
    if node is None and not install_node():
        return False
    node = node_executable()
    WEBCRACK_DIR.mkdir(parents=True, exist_ok=True)
    (WEBCRACK_DIR / "package.json").write_text('{"private":true}\n', encoding="utf-8")
    print("[>] Installing webcrack into tools/webcrack/ (npm; builds isolated-vm)")
    try:
        r = subprocess.run(_npm_cmd(node) + ["install", "--no-audit", "--no-fund",
                                             "--prefix", str(WEBCRACK_DIR),
                                             f"webcrack@{WEBCRACK_VERSION}"],
                           capture_output=True, text=True, timeout=900)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] webcrack install failed ({exc}); JS falls back to the Python cascade.")
        return False
    if r.returncode == 0 and _webcrack_ok():
        print("[+] webcrack installed")
        return True
    print(f"[!] webcrack install failed (likely missing build tools for isolated-vm): "
          f"{(r.stderr or '').strip()[-300:]}")
    return False


# --- PowerShell Core + box-ps (PowerShell sandbox) --------------------------
PWSH_DIR = TOOLS / "pwsh"
PWSH_VERSION = "7.4.6"                          # LTS; MIT
PWSH_BASE = "https://github.com/PowerShell/PowerShell/releases/download/"
BOXPS_DIR = TOOLS / "boxps"
BOXPS_ZIP = "https://github.com/ConnorShride/box-ps/archive/refs/heads/master.zip"  # GPL-3.0


def _pwsh_asset() -> str:
    v, arch = PWSH_VERSION, ("x64" if _arch() == "x86_64" else "arm64")
    if sys.platform.startswith("win"):
        return f"PowerShell-{v}-win-{arch}.zip"
    if sys.platform == "darwin":
        return f"powershell-{v}-osx-{arch}.tar.gz"
    return f"powershell-{v}-linux-{arch}.tar.gz"


def pwsh_executable() -> Path | None:
    for c in (PWSH_DIR / "pwsh.exe", PWSH_DIR / "pwsh", PWSH_DIR / "bin" / "pwsh"):
        if c.is_file():
            return c
    return None


def install_pwsh() -> bool:
    """Portable PowerShell Core into tools/pwsh/ (self-contained, MIT)."""
    if pwsh_executable():
        return True
    name = _pwsh_asset()
    url = f"{PWSH_BASE}v{PWSH_VERSION}/{name}"
    print(f"[>] Provisioning PowerShell Core (for box-ps) into tools/pwsh/: {name}")
    try:
        data = _get(url)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download PowerShell ({exc}); box-ps stays disabled.")
        return False
    import io
    PWSH_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                z.extractall(PWSH_DIR)
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
                try:
                    t.extractall(PWSH_DIR, filter="tar")
                except TypeError:
                    t.extractall(PWSH_DIR)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not extract PowerShell: {exc}")
        return False
    exe = pwsh_executable()
    if exe is None:
        print("[!] PowerShell extracted but pwsh was not found.")
        return False
    if not sys.platform.startswith("win"):
        try:
            exe.chmod(0o755)
        except OSError:
            pass
    print(f"[+] pwsh at {exe}")
    return True


def _boxps_ok() -> bool:
    return any((BOXPS_DIR / n).is_file() for n in ("box-ps.ps1", "BoxPS.ps1"))


def install_boxps() -> bool:
    """box-ps (GPL-3.0) into tools/boxps/. Provisioned here, never shipped in
    this repository; invoked as a separate process by the pwsh runtime."""
    if _boxps_ok():
        return True
    if pwsh_executable() is None and not install_pwsh():
        return False
    print("[>] Provisioning box-ps (PowerShell sandbox) into tools/boxps/")
    try:
        data = _get(BOXPS_ZIP)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download box-ps ({exc}); the PowerShell sandbox stays disabled.")
        return False
    import io
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                z.extractall(tdp)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Could not extract box-ps: {exc}")
            return False
        tops = [p for p in tdp.iterdir() if p.is_dir()]
        if len(tops) != 1:
            print("[!] Unexpected box-ps archive layout.")
            return False
        if BOXPS_DIR.exists():
            shutil.rmtree(BOXPS_DIR)
        shutil.move(str(tops[0]), str(BOXPS_DIR))
    if _boxps_ok():
        print(f"[+] box-ps at {BOXPS_DIR}")
        return True
    print("[!] box-ps extracted but its entry script was not found.")
    return False


PYCDC_DIR = TOOLS / "pycdc"
PYCDC_ZIP = "https://github.com/zrax/pycdc/archive/refs/heads/master.zip"  # MIT


def _pycdc_ok() -> bool:
    for c in (PYCDC_DIR / "pycdc.exe", PYCDC_DIR / "pycdc",
              PYCDC_DIR / "build" / "pycdc", PYCDC_DIR / "build" / "Release" / "pycdc.exe"):
        if c.is_file():
            return True
    return False


def install_pycdc() -> bool:
    """pycdc / Decompyle++ (MIT) into tools/pycdc/ — optional .pyc decompiler.
    Built from source with CMake (like webcrack's native dep); when absent the
    Python engine falls back to bytecode disassembly + string mining."""
    if _pycdc_ok():
        return True
    if shutil.which("cmake") is None:
        print("[!] cmake not found; skipping pycdc (the .pyc decompiler is optional — "
              "the Python engine still disassembles and mines strings).")
        return False
    print("[>] Provisioning pycdc (.pyc decompiler) into tools/pycdc/ — building from source")
    import io
    try:
        data = _get(PYCDC_ZIP)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download pycdc ({exc}); decompilation stays disabled.")
        return False
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                z.extractall(tdp)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Could not extract pycdc: {exc}")
            return False
        tops = [p for p in tdp.iterdir() if p.is_dir()]
        if len(tops) != 1:
            print("[!] Unexpected pycdc archive layout.")
            return False
        src = tops[0]
        build = src / "build"
        try:
            subprocess.run(["cmake", "-S", str(src), "-B", str(build),
                            "-DCMAKE_BUILD_TYPE=Release"], check=True)
            subprocess.run(["cmake", "--build", str(build), "--target", "pycdc",
                            "--config", "Release"], check=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] pycdc build failed ({exc}); decompilation stays disabled.")
            return False
        found = None
        for c in (build / "pycdc", build / "Release" / "pycdc.exe", build / "pycdc.exe"):
            if c.is_file():
                found = c
                break
        if not found:
            hits = list(build.rglob("pycdc*"))
            found = next((h for h in hits if h.is_file() and h.suffix in ("", ".exe")), None)
        if not found:
            print("[!] pycdc built but the binary was not found.")
            return False
        if PYCDC_DIR.exists():
            shutil.rmtree(PYCDC_DIR)
        PYCDC_DIR.mkdir(parents=True, exist_ok=True)
        dest = PYCDC_DIR / found.name
        shutil.copy2(str(found), str(dest))
        try:
            dest.chmod(0o755)
        except OSError:
            pass
    if _pycdc_ok():
        print(f"[+] pycdc at {PYCDC_DIR}")
        return True
    print("[!] pycdc install did not produce a usable binary.")
    return False


CFR_DIR = TOOLS / "cfr"
CFR_VERSION = "0.152"                           # MIT
CFR_URL = f"https://github.com/leibnitz27/cfr/releases/download/{CFR_VERSION}/cfr-{CFR_VERSION}.jar"


def _cfr_ok() -> bool:
    return CFR_DIR.is_dir() and any(CFR_DIR.glob("cfr*.jar"))


def install_cfr() -> bool:
    """CFR (MIT) Java decompiler jar into tools/cfr/ — optional. Just a download
    (no build); run with any JVM on the host. Absent (or no JVM) → the Java
    engine falls back to .class constant-pool mining."""
    if _cfr_ok():
        return True
    print("[>] Downloading the CFR Java decompiler into tools/cfr/")
    try:
        data = _get(CFR_URL)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download CFR ({exc}); .class decompilation stays disabled.")
        return False
    CFR_DIR.mkdir(parents=True, exist_ok=True)
    (CFR_DIR / f"cfr-{CFR_VERSION}.jar").write_bytes(data)
    if _cfr_ok():
        print(f"[+] CFR at {CFR_DIR}")
        return True
    print("[!] CFR download did not produce a jar.")
    return False


def verify() -> None:
    py = _portable_python()
    print("[>] Verifying the portable runtime")
    code = (
        "import sys;"
        "print('python', sys.version.split()[0]);"
        "import importlib;"
        "ok = []\n"
        "for m in ('fastapi','uvicorn','jinja2','multipart','magic'):\n"
        "    try:\n"
        "        importlib.import_module(m); ok.append(m)\n"
        "    except Exception as e:\n"
        "        print('  MISSING', m, '->', e)\n"
        "print('  OK:', ', '.join(ok))\n"
    )
    # Wire bundled libmagic for the check, if present.
    env = None
    mgc = LIBMAGIC_DIR / "magic.mgc"
    if mgc.is_file():
        import os
        # tag: gmzpt
        env = dict(os.environ)
        env.setdefault("MAGIC", str(mgc))
        if sys.platform.startswith("win"):
            env["PATH"] = str(LIBMAGIC_DIR) + os.pathsep + env.get("PATH", "")
    subprocess.run([str(py), "-c", code], check=False, env=env)


def provision(version: str = DEFAULT_VERSION, force: bool = False) -> None:
    install_python(version, force)
    install_deps()
    if sys.platform.startswith("win"):
        install_libmagic_windows()
    install_didier()
    install_officemalscanner()
    install_vipermonkey()
    install_ipdb()
    install_chromium()
    _clear_mark("webcrack")   # an explicit full setup always retries these
    _clear_mark("boxps")
    _clear_mark("pycdc")
    _clear_mark("cfr")
    install_webcrack()   # portable Node + webcrack (JS deobfuscation)
    install_boxps()      # PowerShell Core + box-ps (PowerShell sandbox)
    install_pycdc()      # pycdc (.pyc decompiler, built from source)
    install_cfr()        # CFR (.class decompiler jar; run with the host JVM)
    verify()


def _tool_import_names() -> list[str]:
    """Import names of the tool dependencies to verify in the portable."""
    try:
        from docutracex.deps import TOOL_DEPS  # type: ignore
        return [d.import_name for d in TOOL_DEPS]
    except Exception:  # noqa: BLE001
        return ["magic", "defusedxml"]


def _libmagic_env() -> dict:
    import os
    env = dict(os.environ)
    mgc = LIBMAGIC_DIR / "magic.mgc"
    if mgc.is_file():
        env.setdefault("MAGIC", str(mgc))
        if sys.platform.startswith("win"):
            env["PATH"] = str(LIBMAGIC_DIR) + os.pathsep + env.get("PATH", "")
    return env


def _tool_deps_ok(py: Path) -> bool:
    """True if every tool dependency imports in the portable interpreter."""
    names = _tool_import_names()
    code = "import importlib\n" + "\n".join(f"importlib.import_module({n!r})" for n in names)
    try:
        r = subprocess.run([str(py), "-I", "-c", code], capture_output=True,
                           text=True, errors="replace", timeout=60, env=_libmagic_env())
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


# Optional runtimes healed on start (webcrack, box-ps). A failed attempt writes
# a marker so the (slow) install is not retried on every start — a full
# ``setup_portable_python.py`` run clears the markers and retries.
def _mark_path(name: str) -> Path:
    return TOOLS / f".{name}_provision_failed"


def _marked(name: str) -> bool:
    return _mark_path(name).exists()


def _mark_failed(name: str) -> None:
    try:
        TOOLS.mkdir(parents=True, exist_ok=True)
        _mark_path(name).write_text(
            "Provisioning failed. Delete this file, or run scripts/setup_portable_python.py, to retry.\n")
    except OSError:
        pass


def _clear_mark(name: str) -> None:
    try:
        _mark_path(name).unlink()
    except OSError:
        pass


def _ensure_optional() -> None:
    """Heal the optional runtimes on start: install webcrack and box-ps when
    missing, once (marker-guarded), so updates pick them up without hammering a
    failing build on every start."""
    for name, ok, install in (("webcrack", _webcrack_ok, install_webcrack),
                              ("boxps", _boxps_ok, install_boxps),
                              ("pycdc", _pycdc_ok, install_pycdc),
                              ("cfr", _cfr_ok, install_cfr)):
        try:
            if ok():
                _clear_mark(name)
            elif not _marked(name):
                print(f"[>] Optional runtime '{name}' missing — attempting to provision it...")
                if not install():
                    _mark_failed(name)
                    print(f"[!] '{name}' not provisioned; it will be skipped on future starts. "
                          f"Run scripts/setup_portable_python.py to retry.")
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Optional runtime '{name}' provisioning errored: {exc}")
            _mark_failed(name)


def ensure(version: str = DEFAULT_VERSION) -> bool:
    """Make sure the portable exists AND has its tool dependencies. Best-effort.

    - No portable yet -> full provision (download + install + libmagic).
    - Portable present but tool deps missing (e.g. a new dependency was added)
      -> reinstall deps into it (and refresh libmagic on Windows).
    Never raises: on failure it logs and returns False so the app still starts.
    """
    try:
        if _portable_present():
            py = _portable_python()
            deps_ok = _tool_deps_ok(py)
            didier_ok = _didier_present()
            oms_ok = _officemalscanner_present()
            vm_ok = _vipermonkey_ok()
            ipdb_ok = _ipdb_ok()
            chromium_ok = _chromium_ok()
            _ensure_optional()   # webcrack + box-ps (optional; marker-guarded)
            if deps_ok and didier_ok and oms_ok and vm_ok and ipdb_ok and chromium_ok:
                print(f"[=] Portable Python present with tools OK at {PY_DIR}")
                return True
            if not deps_ok:
                print("[>] Portable present but tool dependencies missing — updating...")
                install_deps()
                if sys.platform.startswith("win"):
                    install_libmagic_windows()
            if not didier_ok:
                install_didier()
            if not oms_ok:
                install_officemalscanner()  # retried on each start until present
            if not vm_ok:
                install_vipermonkey()  # PyPy 2.7 + ViperMonkey; retried until present
            if not ipdb_ok:
                install_ipdb()  # DB-IP Lite + iptoasn (network checks of IPs)
            if not chromium_ok:
                install_chromium()  # screenshots of checked URLs
            return _tool_deps_ok(py)

        print("[>] Portable Python not found — provisioning it now...")
        provision(version, force=False)
        return _portable_present()
    except SystemExit as exc:
        print(f"[!] Provisioning stopped: {exc}")
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Provisioning failed: {exc}")
    print("[!] The app will still start, but analysis tools may be unavailable "
          "until the portable is provisioned.")
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description="Provision the portable Python runtime")
    ap.add_argument("--version", default=DEFAULT_VERSION, help="CPython X.Y (default 3.13)")
    ap.add_argument("--force", action="store_true", help="Reinstall even if present")
    ap.add_argument("--ensure", action="store_true", help="Provision only if missing (used by run.py)")
    ap.add_argument("--libmagic-only", action="store_true", help="Only provision Windows libmagic")
    args = ap.parse_args()

    if args.libmagic_only:
        install_libmagic_windows()
        return
    if args.ensure:
        ensure(args.version)
        return

    provision(args.version, args.force)
    print("\n[+] Done. Start the app with:  python run.py   (or: python -m docutracex)")


if __name__ == "__main__":
    main()
