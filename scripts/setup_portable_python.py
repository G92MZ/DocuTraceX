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
import os
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

# The portable must see only its own site-packages. Without this, a per-user
# site (e.g. %APPDATA%\Python\Python313\site-packages left by another Python
# 3.13) makes pip report packages as "already satisfied" there and skip them,
# and the isolated (-I) tool checks then miss yaml / idna / pydantic.
import os as _os  # noqa: E402
_os.environ["PYTHONNOUSERSITE"] = "1"
TOOLS = ROOT / "tools"
PY_DIR = TOOLS / "python"
LIBMAGIC_DIR = TOOLS / "libmagic"
DIDIER_DIR = TOOLS / "didier"
OMS_DIR = TOOLS / "officemalscanner"

DIDIER_BASE = "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/"
DIDIER_FILES = [
    "oledump.py", "zipdump.py", "pdfid.py", "pdf-parser.py", "emldump.py", "rtfdump.py",
    "decode-vbe.py",  # decodes Script Encoder (.jse/.vbe) payloads
    "1768.py",        # Cobalt Strike beacon / stager configuration (C2 / Beacons tab)
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
    subprocess.run([str(py), "-s", "-m", "pip", "install", "--upgrade", "pip"], check=False)
    print("[>] Installing DocuTraceX + the analysis toolchain into the portable interpreter")
    # The [tools] extra carries every analysis dependency (oletools, YARA,
    # STPyV8, Playwright, pikepdf, …) — they land ONLY on the portable, never on
    # the user's Python. The web service deps come along as base requirements.
    subprocess.run([str(py), "-s", "-m", "pip", "install", "--no-warn-script-location",
                    "-e", f"{ROOT}[tools]"], check=True)


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


IANA_DIR = TOOLS / "iana"
IANA_TLDS_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"


def install_tlds(force: bool = False) -> bool:
    """Official IANA TLD list into tools/iana/ (IOC domain validation).
    Refreshed when older than ~30 days; on failure the app falls back to a
    built-in list, so this never blocks the install."""
    import time as _time

    dest = IANA_DIR / "tlds-alpha-by-domain.txt"
    if dest.is_file() and not force and _time.time() - dest.stat().st_mtime < 30 * 86400:
        return True
    try:
        print("[>] Downloading IANA TLD list")
        data = _get(IANA_TLDS_URL)
        if data.count(b"\n") < 100:
            raise ValueError("list looks empty")
        IANA_DIR.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"[!] IANA TLD list: {exc} (using the built-in list)")
        return dest.is_file()


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


def _node_version(node: Path) -> str:
    """The portable Node's version string (e.g. '22.11.0'), for node-gyp target."""
    try:
        r = subprocess.run([str(node), "-p", "process.versions.node"],
                           capture_output=True, text=True, timeout=30)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:  # noqa: BLE001
        return ""


def _webcrack_build_env(node: Path) -> dict:
    """Pin node-gyp to the portable Node's version and a local, fresh header
    cache. Without this, node-gyp can reuse a stale header cache from another
    Node (e.g. AppData\\...\\node-gyp\\Cache\\20.7.0) and compile isolated-vm
    against the wrong V8 API — the 'v8::SourceLocation is not a member' /
    'PostTaskImpl did not override' errors. Building against headers that match
    the running Node 22 fixes it."""
    import os

    env = dict(os.environ)
    # Drop any inherited node-gyp pins that would point elsewhere.
    for k in list(env):
        if k.lower().startswith("npm_config_") and k.lower() in (
                "npm_config_target", "npm_config_nodedir", "npm_config_devdir",
                "npm_config_target_arch", "npm_config_runtime", "npm_config_arch"):
            env.pop(k, None)
    ver = _node_version(node)
    if ver:
        env["npm_config_target"] = ver            # build headers for THIS Node
    env["npm_config_runtime"] = "node"
    env["npm_config_arch"] = "arm64" if _arch() == "aarch64" else "x64"
    env["npm_config_target_arch"] = env["npm_config_arch"]
    # A fresh, project-local header cache, never the user's shared one.
    env["npm_config_devdir"] = str((TOOLS / ".node-gyp").resolve())
    # isolated-vm's install script runs `node-gyp-build`, which calls plain
    # `node`: with the portable Node first on PATH it picks the bundled
    # prebuilt binary (no compiler needed) instead of failing with
    # '"node" is not recognized' and falling back to a source build.
    env["PATH"] = str(node.parent.resolve()) + os.pathsep + env.get("PATH", "")
    return env


def install_webcrack() -> bool:
    """npm-install webcrack (MIT) into tools/webcrack/. It pulls isolated-vm,
    which builds from source — needs Node build tools on the host; on failure
    webcrack stays disabled and the pure-Python JS cascade is the fallback.

    node-gyp is pinned (``_webcrack_build_env``) to the portable Node's version
    and a local header cache so isolated-vm compiles against the matching V8."""
    if _webcrack_ok():
        return True
    node = node_executable()
    if node is None and not install_node():
        return False
    node = node_executable()
    WEBCRACK_DIR.mkdir(parents=True, exist_ok=True)
    (WEBCRACK_DIR / "package.json").write_text('{"private":true}\n', encoding="utf-8")
    ver = _node_version(node)
    print(f"[>] Installing webcrack into tools/webcrack/ (npm; builds isolated-vm "
          f"against Node {ver or '?'} headers)")
    try:
        r = subprocess.run(_npm_cmd(node) + ["install", "--no-audit", "--no-fund",
                                             "--prefix", str(WEBCRACK_DIR),
                                             f"webcrack@{WEBCRACK_VERSION}"],
                           capture_output=True, text=True, timeout=900,
                           env=_webcrack_build_env(node))
    except Exception as exc:  # noqa: BLE001
        print(f"[!] webcrack install failed ({exc}); JS falls back to the Python cascade.")
        return False
    if r.returncode == 0 and _webcrack_ok():
        print("[+] webcrack installed")
        return True
    # node-gyp writes the real cause to stdout as often as stderr; show both tails.
    tail = ((r.stdout or "")[-800:] + "\n" + (r.stderr or "")[-800:]).strip()
    print(f"[!] webcrack install failed. isolated-vm builds from source and needs "
          f"the Visual Studio C++ Build Tools (and network access to fetch the Node "
          f"headers). Last output:\n{tail}")
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
# Pinned upstream commit (GPL-3.0; built locally, never redistributed).
PYCDC_COMMIT = "b4289760970dbc399684f1e155ec6d1ea1cc787e"
PYCDC_ZIP = f"https://github.com/zrax/pycdc/archive/{PYCDC_COMMIT}.zip"


def _pycdc_ok() -> bool:
    for c in (PYCDC_DIR / "pycdc.exe", PYCDC_DIR / "pycdc",
              PYCDC_DIR / "build" / "pycdc", PYCDC_DIR / "build" / "Release" / "pycdc.exe"):
        if c.is_file():
            return True
    return False


# pycdc is compiled directly (no CMake): with the system C++ compiler on
# macOS/Linux when there is one, otherwise with Zig's bundled clang (``zig c++``)
# installed from PyPI into a throw-away folder — so no Visual Studio Build Tools
# are needed on Windows. The sources are small and need no code generation.
ZIG_PIP = "ziglang==0.15.2"


def _pycdc_sources(src: Path) -> list[Path]:
    """Everything pycdc links: the top-level .cpp files except the separate
    disassembler (pycdas), plus every bytecode table under bytes/."""
    return sorted(p for p in src.glob("*.cpp") if p.name != "pycdas.cpp") + sorted((src / "bytes").glob("*.cpp"))


def _compile_pycdc(cxx: list[str], src: Path, out: Path, env: dict | None = None) -> bool:
    cmd = [*cxx, "-std=c++11", "-O2", f"-I{src}", *map(str, _pycdc_sources(src)), "-o", str(out)]
    print(f"[>] pycdc: compiling with {Path(cxx[0]).name} {' '.join(cxx[1:])} (about a minute)...")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", env=env, timeout=1800)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] pycdc: build failed ({exc})")
        return False
    ok = r.returncode == 0 and out.is_file() and out.stat().st_size > 0
    if not ok:
        print(f"[!] pycdc: build failed:\n{((r.stdout or '') + (r.stderr or ''))[-1500:]}")
        out.unlink(missing_ok=True)
    return ok


def _build_pycdc_system(src: Path, out: Path) -> bool:
    """macOS / Linux: the system C++ compiler (Xcode CLT, gcc, clang) if any."""
    if sys.platform.startswith("win"):
        return False
    cxx = next((shutil.which(c) for c in ("c++", "clang++", "g++") if shutil.which(c)), None)
    return bool(cxx) and _compile_pycdc([cxx], src, out)


def _build_pycdc_zig(src: Path, out: Path) -> bool:
    import os

    py = _portable_python() if _portable_present() else Path(sys.executable)
    zdir = TOOLS / ".zig"
    print(f"[>] pycdc: fetching the Zig C++ toolchain from PyPI ({ZIG_PIP}, ~100 MB, removed after the build)")
    r = subprocess.run([str(py), "-s", "-m", "pip", "install", "--quiet", "--no-deps",
                        "--disable-pip-version-check", "--target", str(zdir), ZIG_PIP])
    zig = next((c for c in (zdir / "ziglang" / "zig.exe", zdir / "ziglang" / "zig") if c.is_file()), None)
    if r.returncode != 0 or zig is None:
        print("[!] pycdc: could not get the Zig toolchain.")
        shutil.rmtree(zdir, ignore_errors=True)
        return False
    env = dict(os.environ)
    env["ZIG_GLOBAL_CACHE_DIR"] = str(zdir / "cache")
    env["ZIG_LOCAL_CACHE_DIR"] = str(zdir / "cache-local")
    try:
        return _compile_pycdc([str(zig), "c++", "-s"], src, out, env)
    finally:
        shutil.rmtree(zdir, ignore_errors=True)


def _build_pycdc_cmake(src: Path) -> Path | None:
    """Fallback: the host's CMake + compiler, when present."""
    if shutil.which("cmake") is None:
        return None
    build = src / "build"
    try:
        subprocess.run(["cmake", "-S", str(src), "-B", str(build), "-DCMAKE_BUILD_TYPE=Release"], check=True)
        subprocess.run(["cmake", "--build", str(build), "--target", "pycdc", "--config", "Release"], check=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] pycdc CMake build failed ({exc}).")
        return None
    for c in (build / "pycdc", build / "Release" / "pycdc.exe", build / "pycdc.exe"):
        if c.is_file():
            return c
    return next((h for h in build.rglob("pycdc*") if h.is_file() and h.suffix in ("", ".exe")), None)


def install_pycdc() -> bool:
    """pycdc / Decompyle++ (GPL-3.0) into tools/pycdc/ — optional .pyc
    decompiler, built from source with Zig's C++ compiler (fetched from PyPI),
    or the host's CMake as a fallback. When absent the Python engine falls
    back to bytecode disassembly + string mining."""
    if _pycdc_ok():
        return True
    print("[>] Provisioning pycdc (.pyc decompiler) into tools/pycdc/ — building from source")
    import io
    try:
        data = _get(PYCDC_ZIP)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download pycdc ({exc}); decompilation stays disabled.")
        return False
    exe = "pycdc.exe" if sys.platform.startswith("win") else "pycdc"
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
        built = tdp / exe
        found = (built if (_build_pycdc_system(src, built) or _build_pycdc_zig(src, built))
                 else _build_pycdc_cmake(src))
        if not found:
            print("[!] pycdc could not be built; decompilation stays disabled "
                  "(the Python engine still disassembles and mines strings).")
            return False
        if PYCDC_DIR.exists():
            shutil.rmtree(PYCDC_DIR)
        PYCDC_DIR.mkdir(parents=True, exist_ok=True)
        dest = PYCDC_DIR / exe
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


def _cfr_jar_ok() -> bool:
    return CFR_DIR.is_dir() and any(CFR_DIR.glob("cfr*.jar"))


def _cfr_ok() -> bool:
    return _cfr_jar_ok() and _java() is not None


# Portable JRE (Eclipse Temurin 21, GPLv2 + Classpath Exception) for CFR, only
# when the host has no JVM. Pinned release; each archive verified by SHA-256.
JRE_DIR = TOOLS / "jre"
JRE_TAG, JRE_VER = "jdk-21.0.12+8", "21.0.12_8"
JRE_BASE = "https://github.com/adoptium/temurin21-binaries/releases/download/"
JRE_SHA256 = {
    ("windows", "x86_64"): "b8aa18fef5edb69bee8618f99677d66d0873d22cb40d974c15ac9ffcdecf73ba",
    ("windows", "aarch64"): "a50ed83b6a88d3127d406713f5057d78f845c3412d59e201dac6db37714af85c",
    ("linux", "x86_64"): "8a379a67c91a3ae61ffb33d46e0a40c7ba35e70713c4db31cfca30492f792eff",
    ("linux", "aarch64"): "5f9c96b656827b9d14ebeda7739e25be554fa6d25669b03847c1df6e869c0679",
    ("mac", "x86_64"): "539706197baea8189c9a677aea5bf44671b74a71baa42dde436e312f2158fa3a",
    ("mac", "aarch64"): "36bb71d6fa5184e12a6483e7662783c2cbd383f5dca8034140f0a84dd5aa797d",
}


def _java() -> Path | None:
    """A JVM: tools/jre/, then JAVA_HOME, then java on PATH (like the app)."""
    import os
    for c in (JRE_DIR / "bin" / "java.exe", JRE_DIR / "bin" / "java"):
        if c.is_file():
            return c
    jh = os.environ.get("JAVA_HOME")
    if jh:
        for c in (Path(jh) / "bin" / "java.exe", Path(jh) / "bin" / "java"):
            if c.is_file():
                return c
    found = shutil.which("java")
    return Path(found) if found else None


def install_jre() -> bool:
    """Download the pinned Temurin JRE into tools/jre/ (bin/java directly under it)."""
    import hashlib
    import io

    osname = "windows" if sys.platform.startswith("win") else ("mac" if sys.platform == "darwin" else "linux")
    arch = _arch()
    sha = JRE_SHA256.get((osname, arch))
    if not sha:
        print(f"[!] No portable JRE for {osname}/{arch}; install a Java runtime to decompile .class files.")
        return False
    ext = "zip" if osname == "windows" else "tar.gz"
    name = f"OpenJDK21U-jre_{'x64' if arch == 'x86_64' else 'aarch64'}_{osname}_hotspot_{JRE_VER}.{ext}"
    print(f"[>] Downloading a portable Java runtime (Temurin 21 JRE, ~45 MB) into tools/jre/: {name}")
    try:
        data = _get(JRE_BASE + JRE_TAG.replace("+", "%2B") + "/" + name)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download the JRE ({exc}); .class decompilation stays disabled.")
        return False
    if hashlib.sha256(data).hexdigest() != sha:
        print("[!] JRE SHA-256 mismatch — NOT installed.")
        return False
    tmp = TOOLS / ".jre_extract"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    if ext == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            z.extractall(tmp)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
            try:
                t.extractall(tmp, filter="tar")   # keeps the executable bits
            except TypeError:
                t.extractall(tmp)
    home = next((p.parent.parent for p in tmp.rglob("java*") if p.parent.name == "bin"
                 and p.name in ("java", "java.exe")), None)
    if home is None:
        print("[!] The JRE archive had no bin/java.")
        shutil.rmtree(tmp, ignore_errors=True)
        return False
    shutil.rmtree(JRE_DIR, ignore_errors=True)
    shutil.move(str(home), str(JRE_DIR))
    shutil.rmtree(tmp, ignore_errors=True)
    java = _java()
    ok = java is not None and JRE_DIR in java.parents
    print(f"[+] Java runtime at {JRE_DIR}" if ok else "[!] JRE extracted but java was not found.")
    return ok


def install_cfr() -> bool:
    """CFR (MIT) Java decompiler jar into tools/cfr/ — optional. Just a download
    (no build); run with any JVM on the host. Absent (or no JVM) → the Java
    engine falls back to .class constant-pool mining."""
    if _cfr_ok():
        return True
    if not _cfr_jar_ok():
        print("[>] Downloading the CFR Java decompiler into tools/cfr/")
        try:
            data = _get(CFR_URL)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Could not download CFR ({exc}); .class decompilation stays disabled.")
            return False
        CFR_DIR.mkdir(parents=True, exist_ok=True)
        (CFR_DIR / f"cfr-{CFR_VERSION}.jar").write_bytes(data)
        if not _cfr_jar_ok():
            print("[!] CFR download did not produce a jar.")
            return False
        print(f"[+] CFR at {CFR_DIR}")
    if _java() is None and not install_jre():   # no JVM on the host → a portable one
        return False
    return _cfr_ok()


# --- Mandiant FLOSS + capa (standalone Windows binaries) --------------------------
# Official self-contained builds (PyInstaller, Apache-2.0): no Python deps, so no
# clash with the portable 3.13 (flare-floss needs binary2strings, which has no
# cp313 Windows wheel). capa's rules and FLIRT signatures are embedded. Pinned
# version + SHA-256 of the release zip: the download is verified before extracting.
# Windows only; elsewhere the PE triage just reports them as not provisioned.
FLOSS_DIR = TOOLS / "floss"
FLOSS_VERSION = "3.2.0"
FLOSS_URL = (f"https://github.com/mandiant/flare-floss/releases/download/"
             f"v{FLOSS_VERSION}/floss-v{FLOSS_VERSION}-windows.zip")
FLOSS_SHA256 = "c0c73bb99d043fedd8e913038b65d1591fd6308cd938d8a91df87b733b369af5"
CAPA_DIR = TOOLS / "capa"
CAPA_VERSION = "10.0.0"
CAPA_URL = (f"https://github.com/mandiant/capa/releases/download/"
            f"v{CAPA_VERSION}/capa-v{CAPA_VERSION}-windows.zip")
CAPA_SHA256 = "8712991044321dbb2a5b0d60f7a5327a50c9c30a295e7ddb5c1088cb17fb59df"


def _floss_ok() -> bool:
    return (FLOSS_DIR / "floss.exe").is_file()


# --- GoReSym (Go symbol / metadata recovery, Go Malware Intelligence) -------------
# Official Mandiant release (MIT), x86-64 builds for Windows, Linux and macOS
# (Windows on ARM and Apple Silicon run them emulated). Pinned + SHA-256.
GORESYM_DIR = TOOLS / "goresym"
GORESYM_VERSION = "v3.4.1"
GORESYM_BASE = f"https://github.com/mandiant/GoReSym/releases/download/{GORESYM_VERSION}/"
GORESYM_ASSETS = {
    "windows": ("GoReSym-windows.zip", "c051f182412197d834bd3cbd91424831b7aadb85dfe6548603873672560a8dea", "GoReSym.exe"),
    "linux": ("GoReSym-linux.zip", "a557124857f95a589f8ce3525119c2d18c7c7fc7c4225c92ff94e3effb38748d", "GoReSym"),
    "darwin": ("GoReSym-mac.zip", "66e487a2c66c6ca7c15e431306a11d00ed6b005aa99c9d4bcf8117aa40657a30", "GoReSym"),
}


def _goresym_ok() -> bool:
    return any((GORESYM_DIR / n).is_file() for n in ("GoReSym.exe", "GoReSym"))


def install_goresym() -> bool:
    """GoReSym into tools/goresym/ — optional; the Go identification falls back
    to its own parser without it."""
    import hashlib
    import io
    import os

    if _goresym_ok():
        return True
    plat = "windows" if sys.platform.startswith("win") else ("darwin" if sys.platform == "darwin" else "linux")
    if plat == "linux" and _arch() != "x86_64":
        print("[=] GoReSym: only x86-64 Linux builds are published; skipped on this architecture.")
        return False
    asset, sha, exe = GORESYM_ASSETS[plat]
    print(f"[>] Downloading GoReSym {GORESYM_VERSION} into tools/goresym/")
    try:
        data = _get(GORESYM_BASE + asset)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download GoReSym ({exc}); Go identification uses its own parser only.")
        return False
    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        print(f"[!] GoReSym: SHA-256 mismatch (got {got}, expected {sha}) — NOT installed.")
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            member = next((m for m in z.namelist() if Path(m).name == exe), None)
            if member is None:
                print(f"[!] GoReSym: {exe} not found in the release zip.")
                return False
            GORESYM_DIR.mkdir(parents=True, exist_ok=True)
            with z.open(member) as src, (GORESYM_DIR / exe).open("wb") as dst:
                shutil.copyfileobj(src, dst)
        if plat != "windows":
            os.chmod(GORESYM_DIR / exe, 0o755)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] GoReSym: could not extract ({exc}).")
        return False
    print(f"[+] GoReSym at {GORESYM_DIR}")
    return True


# --- Rizin + rz-ghidra (code analysis engine: disassembly + decompilation) --------
# The Rizin releases ship no rz-ghidra; the official Cutter bundle does (rizin
# 0.9.1 + core_ghidra + the SLEIGH processor specs), so only the command-line part
# of it is kept: rizin + its libraries + plugins + share/rizin (no Qt, no Python).
# Pinned + SHA-256. LGPL-3.0 (Rizin, rz-ghidra) / Apache-2.0 (Ghidra decompiler).
RIZIN_DIR = TOOLS / "rizin"
CUTTER_VERSION = "v2.5.0"
CUTTER_BASE = f"https://github.com/rizinorg/cutter/releases/download/{CUTTER_VERSION}/"
CUTTER_ASSETS = {
    ("windows", "x86_64"): ("Cutter-v2.5.0-Windows-x86_64.zip",
                            "a04154a03a392dbf5886a629938582f7d23a93636fa0611c3e1c34905b197e69"),
    ("linux", "x86_64"): ("Cutter-v2.5.0-Linux-x86_64.AppImage",
                          "b8ad215d7a9e2af9e1f463511229f16e1f4745a0fb541413e5f4787f949ac0cf"),
    ("darwin", "aarch64"): ("Cutter-v2.5.0-macOS-arm64.dmg",
                            "ec08477489cb7f769d4121e5084b09131b02b6a801ac7a2d5896a67e87193452"),
    ("darwin", "x86_64"): ("Cutter-v2.5.0-macOS-x86_64.dmg",
                           "02a7f1c507239691b151e6cc41a5d33f89d672ec443f12890e31087ad37271a6"),
}


def rizin_executable() -> Path | None:
    for c in (RIZIN_DIR / "rizin.exe", RIZIN_DIR / "bin" / "rizin"):
        if c.is_file():
            return c
    hits = sorted(RIZIN_DIR.glob("**/MacOS/rizin")) + sorted(RIZIN_DIR.glob("**/bin/rizin"))
    return hits[0] if hits else None


def _rizin_ok() -> bool:
    exe = rizin_executable()
    if exe is None or not any(RIZIN_DIR.glob("**/core_ghidra.*")):
        return False
    if sys.platform.startswith("win"):
        # present but unable to start (no VC++ runtime): reinstall, which puts the runtime next to it
        try:
            r = subprocess.run([str(exe), "-v"], capture_output=True, timeout=60, check=False,
                               stdin=subprocess.DEVNULL)
            return r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
    return True


def _copy_tree(src: Path, dst: Path) -> None:
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True, symlinks=True)


VCRUNTIME_DLLS = ("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
                  "concrt140.dll")


def cab_files(blob: bytes) -> dict[str, bytes]:
    """Files of a Microsoft Cabinet (MSZIP or stored folders), pure Python.
    Enough for the Visual C++ redistributable; LZX / Quantum folders are skipped."""
    import struct
    import zlib
    if blob[:4] != b"MSCF":
        return {}
    _size, coff_files = struct.unpack_from("<I4xI", blob, 8)
    n_folders, n_files, flags = struct.unpack_from("<HHH", blob, 26)
    pos = 36
    cb_folder_res = cb_data_res = 0
    if flags & 4:
        cb_hdr_res, cb_folder_res, cb_data_res = struct.unpack_from("<HBB", blob, pos)
        pos += 4 + cb_hdr_res
    for bit in (1, 2):                                    # previous / next cabinet names
        if flags & bit:
            for _ in range(2):
                pos = blob.index(b"\x00", pos) + 1
    folders = []
    for _ in range(n_folders):
        start, n_data, comp = struct.unpack_from("<IHH", blob, pos)
        folders.append((start, n_data, comp & 0x0F))
        pos += 8 + cb_folder_res
    data: list[bytes | None] = []
    for start, n_data, comp in folders:
        if comp not in (0, 1):
            data.append(None)
            continue
        out, p, hist = bytearray(), start, b""
        for _ in range(n_data):
            _csum, cb, _ucb = struct.unpack_from("<IHH", blob, p)
            p += 8 + cb_data_res
            chunk = blob[p:p + cb]
            p += cb
            if comp == 0:
                piece = chunk
            else:                                        # MSZIP: "CK" + deflate, the previous 32 KB as history
                if chunk[:2] != b"CK":
                    raise ValueError("bad MSZIP block")
                d = zlib.decompressobj(-15, zdict=hist) if hist else zlib.decompressobj(-15)
                piece = d.decompress(chunk[2:]) + d.flush()
                hist = piece[-32768:]
            out += piece
        data.append(bytes(out))
    files: dict[str, bytes] = {}
    pos = coff_files
    for _ in range(n_files):
        cb, off, ifold = struct.unpack_from("<IIH", blob, pos)
        end = blob.index(b"\x00", pos + 16)
        name = blob[pos + 16:end].decode("utf-8", "replace")
        pos = end + 1
        if ifold < len(data) and data[ifold] is not None:
            files[name] = data[ifold][off:off + cb]
    return files


def vcruntime_app_local(redist: bytes, dest: Path) -> int:
    """Unpack the x64 VC++ runtime DLLs from Microsoft's vc_redist.x64.exe
    (WiX bundle: an attached cabinet of payloads, one of them the cabinet of
    the runtime files) into ``dest``. Nothing is run. Returns the DLLs written."""
    import re
    import struct
    n = 0
    try:
        for m in re.finditer(rb"MSCF\x00\x00\x00\x00", redist):
            size = struct.unpack_from("<I", redist, m.start() + 8)[0]
            for payload in cab_files(redist[m.start():m.start() + size]).values():
                if payload[:4] != b"MSCF":
                    continue
                inner = cab_files(payload)
                for want in VCRUNTIME_DLLS:
                    body = inner.get(want + "_amd64")
                    if body and body[:2] == b"MZ":
                        (dest / want).write_bytes(body)
                        n += 1
                if n:
                    return n
    except (ValueError, struct.error, OSError) as exc:
        print(f"[!] Visual C++ runtime: {exc}")
    return n


def install_rizin() -> bool:
    """Rizin + rz-ghidra into tools/rizin/ — optional; without it the Go /
    native code analysis (functions, disassembly, pseudocode) is skipped."""
    import hashlib
    import io
    import os

    if _rizin_ok():
        return True
    plat = "windows" if sys.platform.startswith("win") else ("darwin" if sys.platform == "darwin" else "linux")
    asset = CUTTER_ASSETS.get((plat, _arch()))
    if asset is None:
        print(f"[=] Rizin + rz-ghidra: no official build for {plat}/{_arch()}; code analysis stays disabled.")
        return False
    name, sha = asset
    print(f"[>] Downloading Rizin + rz-ghidra (Cutter {CUTTER_VERSION} bundle, ~140 MB) for {plat}")
    try:
        data = _get(CUTTER_BASE + name)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download {name} ({exc}); code analysis stays disabled.")
        return False
    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        print(f"[!] Rizin bundle: SHA-256 mismatch (got {got}, expected {sha}) — NOT installed.")
        return False
    shutil.rmtree(RIZIN_DIR, ignore_errors=True)
    RIZIN_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if plat == "windows":
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for m in z.infolist():
                    rel = m.filename.split("/", 1)[1] if "/" in m.filename else ""
                    low = rel.lower()
                    keep = (low.count("/") == 0 and (low == "rizin.exe" or low.startswith("rz-") and low.endswith(".exe")
                                                     or low.startswith("rz_") and low.endswith(".dll") or low == "z.dll")) \
                        or low.startswith(("lib/rizin/", "share/rizin/"))
                    if not keep or m.is_dir():
                        continue
                    out = RIZIN_DIR / rel
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(m) as src, out.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                # the Visual C++ runtime next to rizin.exe (app-local): nothing to install system-wide
                redist = next((m for m in z.namelist() if m.lower().endswith("/vc_redist.x64.exe")), None)
                if redist:
                    n = vcruntime_app_local(z.read(redist), RIZIN_DIR)
                    print(f"[+] Visual C++ runtime: {n} DLL(s) placed next to rizin.exe (no system install needed)"
                          if n else "[=] Visual C++ runtime: could not be unpacked; install the VC++ 2015-2022 x64 "
                                    "redistributable if Rizin does not start")
        elif plat == "linux":
            with tempfile.TemporaryDirectory() as td:
                app = Path(td) / "cutter.AppImage"
                app.write_bytes(data)
                app.chmod(0o755)
                # the AppImage runtime only unpacks its own squashfs here (no Cutter is started)
                subprocess.run([str(app), "--appimage-extract"], cwd=td, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900)
                usr = Path(td) / "squashfs-root" / "usr"
                (RIZIN_DIR / "bin").mkdir(parents=True, exist_ok=True)
                for b in usr.glob("bin/r*"):
                    if b.name == "rizin" or b.name.startswith("rz-"):
                        shutil.copy2(b, RIZIN_DIR / "bin" / b.name)
                (RIZIN_DIR / "lib").mkdir(parents=True, exist_ok=True)
                for so in usr.glob("lib/librz_*"):
                    shutil.copy2(so, RIZIN_DIR / "lib" / so.name, follow_symlinks=False)
                _copy_tree(usr / "lib" / "rizin", RIZIN_DIR / "lib" / "rizin")
                _copy_tree(usr / "share" / "rizin", RIZIN_DIR / "share" / "rizin")
        else:                                                    # macOS: mount the dmg read-only, copy the app
            with tempfile.TemporaryDirectory() as td:
                dmg = Path(td) / "cutter.dmg"
                dmg.write_bytes(data)
                mnt = Path(td) / "mnt"
                mnt.mkdir()
                subprocess.run(["hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", str(mnt), str(dmg)],
                               check=True, stdout=subprocess.DEVNULL, timeout=600)
                try:
                    app = next(mnt.glob("*.app"))
                    _copy_tree(app, RIZIN_DIR / app.name)
                finally:
                    subprocess.run(["hdiutil", "detach", str(mnt)], stdout=subprocess.DEVNULL, timeout=120)
        exe = rizin_executable()
        if exe and plat != "windows":
            os.chmod(exe, 0o755)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Rizin bundle: could not extract ({exc}).")
        return False
    if not _rizin_ok():
        print("[!] Rizin bundle extracted but rizin / rz-ghidra were not found in it.")
        return False
    print(f"[+] Rizin + rz-ghidra at {RIZIN_DIR}")
    return True


def _capa_ok() -> bool:
    return (CAPA_DIR / "capa.exe").is_file()


def _install_mandiant_exe(name: str, url: str, sha256: str, dest: Path, exe: str) -> bool:
    """Download a pinned release zip, verify its SHA-256, extract only ``exe``."""
    import hashlib
    import io

    if not sys.platform.startswith("win"):
        print(f"[=] {name}: Windows-only standalone build; skipped on this platform.")
        return False
    print(f"[>] Downloading {name} into {dest.relative_to(ROOT)}/")
    try:
        data = _get(url)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download {name} ({exc}); it stays disabled. "
              f"Drop {exe} into {dest} manually (or set DOCUTRACEX_{name.upper()}).")
        return False
    got = hashlib.sha256(data).hexdigest()
    if got != sha256:
        print(f"[!] {name}: SHA-256 mismatch (got {got}, expected {sha256}) — NOT installed.")
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            member = next((m for m in z.namelist() if Path(m).name.lower() == exe.lower()), None)
            if member is None:
                print(f"[!] {name}: {exe} not found in the release zip.")
                return False
            dest.mkdir(parents=True, exist_ok=True)
            with z.open(member) as src, (dest / exe).open("wb") as dst:
                shutil.copyfileobj(src, dst)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] {name}: could not extract ({exc}).")
        return False
    print(f"[+] {name} {exe} at {dest}")
    return True


def install_floss() -> bool:
    """Mandiant FLOSS (decoded/stack/tight strings of PE files) — optional."""
    if _floss_ok():
        return True
    return _install_mandiant_exe("floss", FLOSS_URL, FLOSS_SHA256, FLOSS_DIR, "floss.exe")


def install_capa() -> bool:
    """Mandiant capa (capabilities + ATT&CK of PE files, embedded rules) — optional."""
    if _capa_ok():
        return True
    return _install_mandiant_exe("capa", CAPA_URL, CAPA_SHA256, CAPA_DIR, "capa.exe")




# --- PE unpackers / packer identification --------------------------------------
# These are optional analysis tools. Each is installed independently so a
# failed download never prevents the remaining toolchain from being provisioned.
UPX_DIR = TOOLS / "upx"
SEVENZIP_DIR = TOOLS / "7zip"
DIE_DIR = TOOLS / "die"
INNOEXTRACT_DIR = TOOLS / "innoextract"
NUITKA_DIR = TOOLS / "nuitka-extractor"


UPX_REPO = "upx/upx"
DIE_BINARY_REPO = "horsicq/DIE-engine"
DIE_DB_REPO = "horsicq/Detect-It-Easy"
NUITKA_REPO = "extremecoders-re/nuitka-extractor"
INNOEXTRACT_URL = "https://constexpr.org/innoextract/files/innoextract-1.9/innoextract-1.9-windows.zip"
INNOEXTRACT_SHA256 = "6989342c9b026a00a72a38f23b62a8e6a22cc5de69805cf47d68ac2fec993065"
SEVENZIP_VERSION = "26.02"
# Use the official x64 MSI rather than 7z2602-extra.7z. The Extra archive is
# BCJ2-compressed, which py7zr cannot extract; the MSI supports administrative
# extraction with msiexec and does not require a pre-existing 7-Zip binary.
SEVENZIP_URL = "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-x64.msi"
SEVENZIP_SHA256 = "db407a4f6d4999e5c7bc00ce8a882be94717b56e7fa68140fe3f12605d91643e"


def _github_json(url: str):
    req = urllib.request.Request(url, headers={
        "User-Agent": "DocuTraceX-setup", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _github_asset(repo: str, predicate, *, tag: str | None = None,
                  allow_prerelease: bool = False):
    """Return (asset metadata, bytes) for a matching official GitHub release asset.

    Prefer the release API's SHA-256 digest when GitHub provides one. The caller
    still validates the archive contents before marking the component available.
    """
    if tag:
        releases = [_github_json(f"https://api.github.com/repos/{repo}/releases/tags/{tag}")]
    else:
        releases = _github_json(f"https://api.github.com/repos/{repo}/releases?per_page=30")
    for release in releases:
        if release.get("draft") or (release.get("prerelease") and not allow_prerelease):
            continue
        assets = sorted(release.get("assets", []), key=lambda a: a.get("name", "").lower())
        matches = [a for a in assets if predicate(a.get("name", "").lower())]
        if not matches:
            continue
        asset = matches[0]
        data = _get(asset["browser_download_url"])
        digest = (asset.get("digest") or "").lower()
        if digest.startswith("sha256:"):
            import hashlib
            got = hashlib.sha256(data).hexdigest()
            expected = digest.split(":", 1)[1]
            if got != expected:
                raise ValueError(f"SHA-256 mismatch for {asset['name']}: {got} != {expected}")
        return asset, data
    raise RuntimeError(f"No matching release asset found for {repo}")


def _safe_extract_zip(data: bytes, dest: Path, *, flatten_root: bool = False) -> list[Path]:
    """Extract a trusted tool ZIP, rejecting path traversal and optionally
    stripping a single common top-level directory (portable release layout)."""
    import io
    written: list[Path] = []
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        files = [i for i in z.infolist() if not i.is_dir()]
        strip = ""
        if flatten_root and files:
            first = {Path(i.filename.replace("\\\\", "/")).parts[0]
                     for i in files if Path(i.filename.replace("\\\\", "/")).parts}
            if len(first) == 1:
                candidate = next(iter(first))
                if all(len(Path(i.filename.replace("\\\\", "/")).parts) > 1
                       for i in files):
                    strip = candidate
        root = dest.resolve()
        for info in files:
            name = info.filename.replace("\\\\", "/")
            parts = Path(name).parts
            if not parts or any(x in ("..", "") for x in parts):
                continue
            if strip and parts[0] == strip:
                parts = parts[1:]
            if not parts:
                continue
            target = (dest / Path(*parts)).resolve()
            try:
                target.relative_to(root)
            except ValueError:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            written.append(target)
    return written


def _safe_extract_7z(data: bytes, dest: Path) -> list[Path]:
    """Extract a 7-Zip archive with the portable py7zr dependency."""
    if not _portable_present():
        raise RuntimeError("portable Python is not available")
    written: list[Path] = []
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        archive = Path(td) / "payload.7z"
        extract_dir = Path(td) / "extract"
        extract_dir.mkdir()
        archive.write_bytes(data)
        code = ("import py7zr,sys; "
                "z=py7zr.SevenZipFile(sys.argv[1], mode='r'); "
                "z.extractall(path=sys.argv[2]); z.close()")
        r = subprocess.run([str(_portable_python()), "-I", "-c", code,
                            str(archive), str(extract_dir)],
                           capture_output=True, text=True, timeout=180)
        if r.returncode:
            raise RuntimeError((r.stderr or r.stdout or "py7zr extraction failed")[-1200:])
        root = dest.resolve()
        for src in extract_dir.rglob("*"):
            if not src.is_file():
                continue
            rel = src.relative_to(extract_dir)
            target = (dest / rel).resolve()
            try:
                target.relative_to(root)
            except ValueError:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
            written.append(target)
    return written


def _find_tool_file(directory: Path, names: tuple[str, ...]) -> Path | None:
    wanted = {n.lower() for n in names}
    for p in directory.rglob("*"):
        if p.is_file() and p.name.lower() in wanted:
            return p
    return None


def _install_github_zip_tool(repo: str, predicate, dest: Path,
                             exe_names: tuple[str, ...], label: str,
                             *, flatten_root: bool = True) -> bool:
    try:
        asset, data = _github_asset(repo, predicate)
        if not zipfile.is_zipfile(__import__("io").BytesIO(data)):
            raise ValueError(f"{asset['name']} is not a ZIP archive")
        _safe_extract_zip(data, dest, flatten_root=flatten_root)
        exe = _find_tool_file(dest, exe_names)
        if exe is None:
            raise RuntimeError(f"{', '.join(exe_names)} not found in {asset['name']}")
        # Normalise the executable to the path expected by DocuTraceX.
        expected = dest / exe_names[0]
        if exe.resolve() != expected.resolve():
            shutil.copy2(exe, expected)
        print(f"[+] {label}: {expected}")
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"[!] {label} could not be provisioned ({exc}); it remains optional.")
        return False


def _upx_ok() -> bool:
    return (UPX_DIR / "upx.exe").is_file() if sys.platform.startswith("win") else (UPX_DIR / "upx").is_file()


def install_upx() -> bool:
    if _upx_ok():
        return True
    if not sys.platform.startswith("win"):
        print("[=] UPX automatic provisioning currently targets Windows; skipped.")
        return False
    arch = "win64" if _arch() == "x86_64" else "win32"
    print("[>] Provisioning UPX from the official GitHub release...")
    return _install_github_zip_tool(
        UPX_REPO, lambda n: n.endswith(f"-{arch}.zip") and n.startswith("upx-"),
        UPX_DIR, ("upx.exe",), "UPX")


def _sevenzip_ok() -> bool:
    return (SEVENZIP_DIR / "7z.exe").is_file() and (SEVENZIP_DIR / "7z.dll").is_file()


def install_7zip() -> bool:
    """Provision the official 7-Zip CLI/DLL using MSI administrative extraction.

    Do not use py7zr for 7-Zip Extra: that archive uses the BCJ2 filter, which
    py7zr does not support. MSI administrative extraction is self-contained and
    places the files under tools/ without installing 7-Zip system-wide.
    """
    if _sevenzip_ok():
        return True
    if not sys.platform.startswith("win"):
        print("[=] 7-Zip automatic provisioning currently targets Windows; skipped.")
        return False
    if _arch() != "x86_64":
        print("[!] 7-Zip automatic provisioning currently has an official x64 MSI only; skipped.")
        return False

    msiexec = shutil.which("msiexec.exe") or shutil.which("msiexec")
    if not msiexec:
        candidate = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "msiexec.exe"
        if candidate.is_file():
            msiexec = str(candidate)
    if not msiexec:
        print("[!] 7-Zip: msiexec.exe was not found; cannot extract the official MSI.")
        return False

    print(f"[>] Downloading official 7-Zip {SEVENZIP_VERSION} x64 MSI...")
    try:
        import hashlib
        data = _get(SEVENZIP_URL)
        got = hashlib.sha256(data).hexdigest()
        if got.lower() != SEVENZIP_SHA256.lower():
            raise ValueError(f"SHA-256 mismatch ({got})")

        with tempfile.TemporaryDirectory(prefix="docutracex-7zip-") as td:
            work = Path(td)
            msi = work / f"7z{SEVENZIP_VERSION.replace('.', '')}-x64.msi"
            stage = work / "admin-image"
            stage.mkdir()
            msi.write_bytes(data)

            # /a performs an administrative image extraction; TARGETDIR is the
            # temporary staging directory, not Program Files or the registry.
            cmd = [msiexec, "/a", str(msi), "/qn", "/norestart",
                   f"TARGETDIR={stage}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
            if result.returncode not in (0, 3010):
                detail = (result.stderr or result.stdout or
                          f"msiexec exit code {result.returncode}")
                raise RuntimeError(detail[-1600:])

            src_exe = _find_tool_file(stage, ("7z.exe",))
            src_dll = _find_tool_file(stage, ("7z.dll",))
            if not src_exe or not src_dll:
                raise RuntimeError("7-Zip MSI administrative image did not contain both 7z.exe and 7z.dll")

            # Copy the complete 7-Zip program directory (including any support
            # files) and normalise the two paths required by DocuTraceX.
            SEVENZIP_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src_exe.parent, SEVENZIP_DIR, dirs_exist_ok=True)
            if not (SEVENZIP_DIR / "7z.exe").is_file():
                shutil.copy2(src_exe, SEVENZIP_DIR / "7z.exe")
            if not (SEVENZIP_DIR / "7z.dll").is_file():
                shutil.copy2(src_dll, SEVENZIP_DIR / "7z.dll")

        if not _sevenzip_ok():
            raise RuntimeError("7z.exe or 7z.dll is missing after MSI extraction")
        print(f"[+] 7-Zip {SEVENZIP_VERSION} CLI + DLL installed at {SEVENZIP_DIR}")
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"[!] 7-Zip could not be provisioned ({exc}); it remains optional.")
        return False


def _die_ok() -> bool:
    exe = _find_tool_file(DIE_DIR, ("diec.exe",))
    db = DIE_DIR / "db"
    return bool(exe and db.is_dir() and any(db.rglob("*")))


def install_die() -> bool:
    if not sys.platform.startswith("win"):
        print("[=] Detect It Easy automatic provisioning currently targets Windows; skipped.")
        return False
    DIE_DIR.mkdir(parents=True, exist_ok=True)
    exe_ok = _find_tool_file(DIE_DIR, ("diec.exe",)) is not None
    if not exe_ok:
        print("[>] Downloading Detect It Easy portable Windows build...")
        # Official releases may change their archive naming; select a Windows
        # x64 portable ZIP by its asset metadata instead of hard-coding a tag.
        try:
            asset, data = _github_asset(
                DIE_BINARY_REPO,
                lambda n: ("win64" in n or "windows" in n) and
                          ("portable" in n or "die" in n) and
                          (n.endswith(".zip") or n.endswith(".7z")))
            if asset["name"].lower().endswith(".7z"):
                _safe_extract_7z(data, DIE_DIR)
            else:
                _safe_extract_zip(data, DIE_DIR, flatten_root=True)
            if _find_tool_file(DIE_DIR, ("diec.exe",)) is None:
                raise RuntimeError(f"diec.exe not found in {asset['name']}")
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Detect It Easy binary download failed ({exc}).")
            return False
    # The upstream project publishes its signature database as a separate
    # release asset (tag 'db'); the CLI without this database is not useful.
    db_dir = DIE_DIR / "db"
    if not db_dir.is_dir() or not any(db_dir.rglob("*")):
        print("[>] Downloading Detect It Easy signature database...")
        try:
            asset, data = _github_asset(DIE_DB_REPO, lambda n: n == "db.zip", tag="db",
                                        allow_prerelease=True)
            _safe_extract_zip(data, DIE_DIR, flatten_root=False)
            if not db_dir.is_dir():
                # Some DB archives contain a wrapper directory; locate and move it.
                found = next((p for p in DIE_DIR.rglob("db") if p.is_dir()), None)
                if found and found != db_dir:
                    shutil.copytree(found, db_dir, dirs_exist_ok=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Detect It Easy database download failed ({exc}).")
    if _die_ok():
        print(f"[+] Detect It Easy (diec + db) installed at {DIE_DIR}")
        return True
    print("[!] Detect It Easy is incomplete; diec.exe and its db/ folder are both required.")
    return False


def _innoextract_ok() -> bool:
    return (INNOEXTRACT_DIR / "innoextract.exe").is_file()


def install_innoextract() -> bool:
    if _innoextract_ok():
        return True
    if not sys.platform.startswith("win"):
        print("[=] innoextract automatic provisioning currently targets Windows; skipped.")
        return False
    print("[>] Downloading innoextract 1.9 Windows binaries...")
    try:
        import hashlib
        data = _get(INNOEXTRACT_URL)
        got = hashlib.sha256(data).hexdigest()
        if got != INNOEXTRACT_SHA256:
            raise ValueError(f"SHA-256 mismatch ({got})")
        files = _safe_extract_zip(data, INNOEXTRACT_DIR, flatten_root=True)
        if not any(p.name.lower() == "innoextract.exe" for p in files):
            raise RuntimeError("innoextract.exe not found in the official archive")
        print(f"[+] innoextract installed at {INNOEXTRACT_DIR}")
        return _innoextract_ok()
    except Exception as exc:  # noqa: BLE001
        print(f"[!] innoextract could not be provisioned ({exc}); it remains optional.")
        return False


def _nuitka_extractor_ok() -> bool:
    return (NUITKA_DIR / "nuitka-extractor.exe").is_file()


def install_nuitka_extractor() -> bool:
    if _nuitka_extractor_ok():
        return True
    if not sys.platform.startswith("win"):
        print("[=] nuitka-extractor automatic provisioning currently targets Windows; skipped.")
        return False
    print("[>] Downloading Nuitka Extractor Windows binary...")
    try:
        try:
            asset, data = _github_asset(
                NUITKA_REPO,
                lambda n: ("windows" in n or "win" in n) and
                          ("amd64" in n or "x64" in n or "win64" in n) and
                          (n.endswith(".exe") or n.endswith(".zip")))
        except Exception:
            # Some tagged builds publish a single generically named Windows
            # executable rather than including the architecture in its name.
            asset, data = _github_asset(
                NUITKA_REPO,
                lambda n: "nuitka" in n and (n.endswith(".exe") or n.endswith(".zip"))
                          and not any(x in n for x in ("linux", "darwin", "macos")))
        NUITKA_DIR.mkdir(parents=True, exist_ok=True)
        if asset["name"].lower().endswith(".zip"):
            files = _safe_extract_zip(data, NUITKA_DIR, flatten_root=True)
            exe = next((p for p in files if p.suffix.lower() == ".exe" and
                        "nuitka" in p.name.lower()), None)
            if not exe:
                raise RuntimeError(f"No Nuitka extractor executable in {asset['name']}")
            shutil.copy2(exe, NUITKA_DIR / "nuitka-extractor.exe")
        else:
            (NUITKA_DIR / "nuitka-extractor.exe").write_bytes(data)
        print(f"[+] nuitka-extractor installed at {NUITKA_DIR}")
        return _nuitka_extractor_ok()
    except Exception as exc:  # noqa: BLE001
        print(f"[!] nuitka-extractor could not be provisioned ({exc}); it remains optional.")
        return False


def _portable_import_ok(module: str) -> bool:
    if not _portable_present():
        return False
    try:
        r = subprocess.run([str(_portable_python()), "-I", "-c", f"import {module}"],
                           capture_output=True, text=True, timeout=45)
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _install_portable_pip_package(package: str, module: str) -> bool:
    if _portable_import_ok(module):
        return True
    if not _portable_present():
        print(f"[!] Cannot install {package}: portable Python is missing.")
        return False
    py = _portable_python()
    print(f"[>] Installing {package} into the portable Python...")
    r = subprocess.run([str(py), "-s", "-m", "pip", "install", "--disable-pip-version-check",
                        "--no-warn-script-location", package], capture_output=True, text=True)
    if r.returncode and (r.stderr or r.stdout):
        print((r.stderr or r.stdout)[-1200:])
    ok = _portable_import_ok(module)
    print(f"[+] {package} installed in portable Python." if ok else
          f"[!] {package} is still unavailable in portable Python.")
    return ok


def install_autoit_ripper() -> bool:
    return _install_portable_pip_package("autoit-ripper", "autoit_ripper")


def install_evbunpack() -> bool:
    return _install_portable_pip_package("evbunpack", "evbunpack")


EMBER_DIR = ROOT / "tools" / "ember"
EMBER_URL = "https://huggingface.co/joyce8/EMBER2024-benchmark-models/resolve/main/EMBER2024_{}.model"
# patched oscrypto: PyPI's 1.3.0 cannot parse OpenSSL 3.0.1x version strings
# (Linux/macOS); signify 0.7.1 (EMBER's Authenticode features) imports it.
OSCRYPTO_FIX = "oscrypto @ git+https://github.com/wbond/oscrypto.git@d5f3437ed24257895ae1edd9e503cfb352e635a8"


def _ember_models() -> dict:
    import json
    f = ROOT / "docutracex" / "ml" / "ember_thresholds.json"
    try:
        return json.loads(f.read_text(encoding="utf-8")).get("models") or {}
    except (OSError, ValueError):
        return {}


def _ember_ok() -> bool:
    models = _ember_models()
    return bool(models) and all((EMBER_DIR / f"EMBER2024_{k}.model").is_file() for k in models)


def install_ember() -> bool:
    """EMBER2024 LightGBM detection models (Machine Learning tab): ~26 MB from
    Hugging Face, each verified against its pinned SHA-256."""
    import hashlib

    models = _ember_models()
    if not models:
        print("[!] ember: pinned model list (docutracex/ml/ember_thresholds.json) missing.")
        return False
    if not sys.platform.startswith("win"):
        py = _portable_python()
        r = subprocess.run([str(py), "-c", "import signify.authenticode"], capture_output=True, text=True)
        if r.returncode != 0 and "libcrypto" in (r.stderr or ""):
            print("[>] ember: installing the patched oscrypto (OpenSSL 3 version detection)")
            subprocess.run([str(py), "-m", "pip", "install", "--force-reinstall", "--no-deps", OSCRYPTO_FIX],
                           check=False)
    EMBER_DIR.mkdir(parents=True, exist_ok=True)
    ok = True
    for name, meta in models.items():
        dest = EMBER_DIR / f"EMBER2024_{name}.model"
        if dest.is_file() and hashlib.sha256(dest.read_bytes()).hexdigest() == meta.get("sha256"):
            continue
        print(f"[>] ember: downloading EMBER2024_{name}.model")
        try:
            data = _get(EMBER_URL.format(name))
        except Exception as exc:  # noqa: BLE001
            print(f"[!] ember: could not download {name} ({exc}).")
            ok = False
            continue
        got = hashlib.sha256(data).hexdigest()
        if got != meta.get("sha256"):
            print(f"[!] ember: SHA-256 mismatch for {name} (got {got}) — NOT installed.")
            ok = False
            continue
        dest.write_bytes(data)
    ok = _install_ember_extra() and ok
    if ok:
        print(f"[+] EMBER2024 models at {EMBER_DIR}")
    return ok


_EMBER_CONVERT = r"""
import io, pickle, sys
from pathlib import Path
import lightgbm

SAFE = {("lightgbm.basic", "Booster"), ("collections", "defaultdict"), ("collections", "OrderedDict"),
        ("builtins", "dict"), ("builtins", "list"), ("builtins", "set"), ("builtins", "tuple"),
        ("builtins", "int"), ("builtins", "float"), ("builtins", "str"), ("builtins", "bool"),
        ("numpy", "dtype"), ("numpy.core.multiarray", "scalar"), ("numpy._core.multiarray", "scalar"),
        ("numpy.core.multiarray", "_reconstruct"), ("numpy._core.multiarray", "_reconstruct"),
        ("numpy", "ndarray")}

class Only(pickle.Unpickler):          # data containers + LightGBM boosters only
    def find_class(self, module, name):
        if (module, name) in SAFE:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"blocked {module}.{name}")

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
boosters = Only(io.BytesIO(src.read_bytes())).load()
dst.mkdir(parents=True, exist_ok=True)
for i, b in enumerate(boosters):
    # bytes, not text: on Windows write_text would turn \n into \r\n and break the
    # byte offsets LightGBM keeps in tree_sizes=
    (dst / f"{i:03d}.txt").write_bytes(b.model_to_string().encode("utf-8"))
print(len(boosters))
"""


def _install_ember_extra() -> bool:
    """Tag models (behaviour, packer, file property, exploit, group: one LightGBM
    booster per tag, published as a pickle) → plain text boosters under
    tools/ember/tags/<kind>/, loaded with an unpickler that only builds Boosters.
    The family model (459 MB) only with DOCUTRACEX_EMBER_FAMILY=1."""
    import hashlib
    import json
    import os

    f = ROOT / "docutracex" / "ml" / "ember_thresholds.json"
    try:
        extra = json.loads(f.read_text(encoding="utf-8")).get("extra_models") or {}
    except (OSError, ValueError):
        return True
    ok = True
    py = _portable_python()
    for kind, meta in extra.items():
        if kind == "family":
            dest = EMBER_DIR / "EMBER2024_family.model"
            if dest.is_file() or os.environ.get("DOCUTRACEX_EMBER_FAMILY") != "1":
                continue
        elif any((EMBER_DIR / "tags" / kind).glob("*.txt")):
            continue
        print(f"[>] ember: downloading EMBER2024_{kind}.model ({meta.get('size', 0) >> 20} MB)")
        try:
            data = _get(EMBER_URL.format(kind))
        except Exception as exc:  # noqa: BLE001
            print(f"[!] ember: could not download {kind} ({exc}).")
            ok = False
            continue
        if hashlib.sha256(data).hexdigest() != meta.get("sha256"):
            print(f"[!] ember: SHA-256 mismatch for {kind} — NOT installed.")
            ok = False
            continue
        if kind == "family":
            (EMBER_DIR / "EMBER2024_family.model").write_bytes(data)
            continue
        tmp = EMBER_DIR / f"{kind}.pickle.tmp"
        tmp.write_bytes(data)
        r = subprocess.run([str(py), "-c", _EMBER_CONVERT, str(tmp), str(EMBER_DIR / "tags" / kind)],
                           capture_output=True, text=True)
        tmp.unlink(missing_ok=True)
        if r.returncode != 0:
            print(f"[!] ember: could not convert {kind}: {(r.stderr or '').strip()[-300:]}")
            ok = False
    return ok


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
    install_tlds()
    install_chromium()
    _clear_mark("webcrack")   # an explicit full setup always retries these
    _clear_mark("boxps")
    _clear_mark("pycdc")
    _clear_mark("cfr")
    _clear_mark("floss")
    _clear_mark("capa")
    _clear_mark("goresym")
    _clear_mark("rizin")
    _clear_mark("ilspy")
    _clear_mark("de4dot")
    install_webcrack()   # portable Node + webcrack (JS deobfuscation)
    install_boxps()      # PowerShell Core + box-ps (PowerShell sandbox)
    install_pycdc()      # pycdc (.pyc decompiler, built from source)
    install_cfr()        # CFR (.class decompiler jar; run with the host JVM)
    install_floss()      # Mandiant FLOSS standalone (PE obfuscated strings; Windows)
    install_capa()       # Mandiant capa standalone (PE capabilities/ATT&CK; Windows)
    install_goresym()    # Mandiant GoReSym (Go metadata recovery; Go Malware Intelligence)
    install_rizin()      # Rizin + rz-ghidra (code analysis: functions, disassembly, pseudocode)
    install_ilspy()      # ILSpy CLI + portable .NET runtime (.NET decompilation, on demand)
    install_de4dot()     # de4dot-cex, --strtyp none only (Windows / Mono)
    # PE packer / installer unpackers. Each is optional and independently guarded.
    for _name in ("upx", "7zip", "die", "innoextract", "nuitka-extractor",
                  "autoit-ripper", "evbunpack"):
        _clear_mark(_name)
    install_upx()
    install_7zip()
    install_die()
    install_innoextract()
    install_nuitka_extractor()
    install_autoit_ripper()
    install_evbunpack()
    _clear_mark("ember")
    install_ember()      # EMBER2024 LightGBM models (Machine Learning tab)
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


# --- .NET decompilation: ILSpy CLI (MIT) on a portable .NET runtime (MIT), and
# de4dot-cex (GPL-3) used ONLY with ``--strtyp none``. Both run in a separate
# process, on demand. Nothing is installed globally: everything under tools/.
DOTNET_DIR = TOOLS / "dotnet"
DOTNET_CHANNEL = "8.0"                           # ilspycmd 9.x targets net8.0
DOTNET_META = f"https://builds.dotnet.microsoft.com/dotnet/release-metadata/{DOTNET_CHANNEL}/releases.json"
ILSPY_DIR = TOOLS / "ilspy"
ILSPY_VERSION = "9.1.0.7988"                     # ilspycmd (MIT), from nuget.org
ILSPY_NUPKG = f"https://api.nuget.org/v3-flatcontainer/ilspycmd/{ILSPY_VERSION}/ilspycmd.{ILSPY_VERSION}.nupkg"
ILSPY_REG = f"https://api.nuget.org/v3/registration5-semver1/ilspycmd/{ILSPY_VERSION}.json"
DE4DOT_DIR = TOOLS / "de4dot"
DE4DOT_REPO, DE4DOT_TAG = "ViRb3/de4dot-cex", "v4.0.0"   # GPL-3: downloaded here, never in the repo


def _dotnet_exe() -> Path | None:
    for c in (DOTNET_DIR / "dotnet.exe", DOTNET_DIR / "dotnet"):
        if c.is_file():
            return c
    return None


def _dotnet_ok() -> bool:
    exe = _dotnet_exe()
    return exe is not None and any((DOTNET_DIR / "shared" / "Microsoft.NETCore.App").glob(f"{DOTNET_CHANNEL}.*"))


def _ilspy_dll() -> Path | None:
    found = sorted(ILSPY_DIR.glob("tools/net*/any/ilspycmd.dll")) if ILSPY_DIR.is_dir() else []
    return found[-1] if found else None


def _ilspy_ok() -> bool:
    return _dotnet_ok() and _ilspy_dll() is not None


def _dotnet_rid() -> str | None:
    osname = "win" if sys.platform.startswith("win") else ("osx" if sys.platform == "darwin" else "linux")
    try:
        arch = {"x86_64": "x64", "aarch64": "arm64"}[_arch()]
    except (KeyError, SystemExit):
        return None
    return f"{osname}-{arch}"


def install_dotnet_runtime() -> bool:
    """The latest .NET 8 runtime (MIT) into tools/dotnet/, verified with the
    SHA-512 Microsoft publishes in its release metadata."""
    import hashlib
    import io
    import os

    if _dotnet_ok():
        return True
    rid = _dotnet_rid()
    if rid is None:
        print("[!] .NET runtime: unsupported architecture; .NET decompilation stays disabled.")
        return False
    try:
        meta = json.loads(_get(DOTNET_META))
        rel = next(r for r in meta["releases"] if r.get("runtime", {}).get("files"))
        ext = "zip" if rid.startswith("win") else "tar.gz"
        f = next(x for x in rel["runtime"]["files"]
                 if x.get("rid") == rid and x.get("name") == f"dotnet-runtime-{rid}.{ext}")
        print(f"[>] Downloading the .NET {rel['runtime']['version']} runtime (~30 MB) into tools/dotnet/")
        data = _get(f["url"])
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download the .NET runtime ({exc}); .NET decompilation stays disabled.")
        return False
    if hashlib.sha512(data).hexdigest().lower() != str(f.get("hash", "")).lower():
        print("[!] .NET runtime: SHA-512 mismatch — NOT installed.")
        return False
    shutil.rmtree(DOTNET_DIR, ignore_errors=True)
    try:
        if ext == "zip":
            _safe_extract_zip(data, DOTNET_DIR)
        else:
            DOTNET_DIR.mkdir(parents=True, exist_ok=True)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
                try:
                    t.extractall(DOTNET_DIR, filter="tar")
                except TypeError:
                    t.extractall(DOTNET_DIR)
            if (DOTNET_DIR / "dotnet").is_file():
                os.chmod(DOTNET_DIR / "dotnet", 0o755)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] .NET runtime: could not extract ({exc}).")
        return False
    ok = _dotnet_ok()
    print(f"[+] .NET runtime at {DOTNET_DIR}" if ok else "[!] .NET runtime extracted but dotnet was not found.")
    return ok


def install_ilspy() -> bool:
    """ilspycmd (ILSpy command line, MIT) into tools/ilspy/ from its nuget
    package (checked against the SHA-512 in the nuget.org catalog), plus the
    portable .NET runtime it runs on. Optional: without it the .NET view keeps
    the IL listing and the Decompile buttons say it is not provisioned."""
    import base64
    import hashlib

    if _ilspy_ok():
        return True
    if not install_dotnet_runtime():
        return False
    if _ilspy_dll() is None:
        print(f"[>] Downloading ilspycmd {ILSPY_VERSION} into tools/ilspy/")
        try:
            data = _get(ILSPY_NUPKG)
            reg = json.loads(_get(ILSPY_REG))
            entry = reg.get("catalogEntry")
            cat = json.loads(_get(entry)) if isinstance(entry, str) else (entry or {})
            want = cat.get("packageHash", "")
            if cat.get("packageHashAlgorithm", "SHA512").upper() != "SHA512" or not want:
                raise ValueError("no SHA-512 in the nuget catalog")
            if base64.b64encode(hashlib.sha512(data).digest()).decode() != want:
                print("[!] ilspycmd: SHA-512 mismatch with the nuget catalog — NOT installed.")
                return False
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Could not download ilspycmd ({exc}); .NET decompilation stays disabled.")
            return False
        shutil.rmtree(ILSPY_DIR, ignore_errors=True)
        _safe_extract_zip(data, ILSPY_DIR)
    ok = _ilspy_ok()
    print(f"[+] ILSpy CLI at {ILSPY_DIR}" if ok else "[!] ilspycmd extracted but its dll was not found.")
    return ok


def _de4dot_exe() -> Path | None:
    if not DE4DOT_DIR.is_dir():
        return None
    found = sorted(DE4DOT_DIR.rglob("de4dot*.exe"), key=lambda p: ("x64" not in p.name, "net4" not in str(p), len(str(p))))
    return found[0] if found else None


def _de4dot_ok() -> bool:
    return _de4dot_exe() is not None and (sys.platform.startswith("win") or shutil.which("mono") is not None)


def install_de4dot() -> bool:
    """de4dot-cex (GPL-3) into tools/de4dot/ — optional, downloaded here and
    never shipped in the repo. It is a .NET Framework program: it runs with the
    Framework built into Windows (elsewhere only if Mono is installed).
    DocuTraceX runs it ONLY with ``--strtyp none`` (renaming + control-flow
    cleanup; it never executes or emulates the sample's methods)."""
    if _de4dot_ok():
        return True
    if not sys.platform.startswith("win") and shutil.which("mono") is None:
        print("[=] de4dot: .NET Framework tool; needs Windows (or Mono). Skipped; ILSpy decompiles without it.")
        return False
    print(f"[>] Downloading de4dot-cex {DE4DOT_TAG} (GPL-3) into tools/de4dot/")
    try:
        _asset, data = _github_asset(DE4DOT_REPO, lambda n: n.endswith(".zip"), tag=DE4DOT_TAG)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not download de4dot ({exc}); ILSpy decompiles without the cleanup step.")
        return False
    shutil.rmtree(DE4DOT_DIR, ignore_errors=True)
    try:
        _safe_extract_zip(data, DE4DOT_DIR, flatten_root=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] de4dot: could not extract ({exc}).")
        return False
    ok = _de4dot_ok()
    print(f"[+] de4dot at {_de4dot_exe()}" if ok else "[!] de4dot extracted but de4dot.exe was not found.")
    return ok


# Optional runtimes healed on start (webcrack, box-ps). A failed attempt writes
# a marker so the (slow) install is not retried on every start — a full
# ``setup_portable_python.py`` run clears the markers and retries.
def _mark_path(name: str) -> Path:
    return TOOLS / f".{name}_provision_failed"


def _app_version() -> str:
    try:
        return (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _marked(name: str) -> bool:
    """A failed attempt is remembered only for the version that made it: after
    an update (which may carry the fix) the install is tried once more."""
    try:
        first = _mark_path(name).read_text(encoding="utf-8").splitlines()[0].strip()
    except (OSError, IndexError):
        return False
    return first == f"version {_app_version()}"


def _mark_failed(name: str) -> None:
    try:
        TOOLS.mkdir(parents=True, exist_ok=True)
        _mark_path(name).write_text(
            f"version {_app_version()}\n"
            "Provisioning failed. Press Retry in Diagnostics, delete this file, or run "
            "scripts/setup_portable_python.py, to retry.\n", encoding="utf-8")
    except OSError:
        pass


def _clear_mark(name: str) -> None:
    try:
        _mark_path(name).unlink()
    except OSError:
        pass


def _ensure_optional() -> None:
    """Heal optional runtimes and PE unpackers on start, once per app version
    after a failed attempt (marker-guarded), so updates pick them up without
    hammering a failing download or build on every start."""
    for name, ok, install in (("webcrack", _webcrack_ok, install_webcrack),
                              ("boxps", _boxps_ok, install_boxps),
                              ("pycdc", _pycdc_ok, install_pycdc),
                              ("cfr", _cfr_ok, install_cfr),
                              ("floss", _floss_ok, install_floss),
                              ("capa", _capa_ok, install_capa),
                              ("goresym", _goresym_ok, install_goresym),
                              ("rizin", _rizin_ok, install_rizin),
                              ("upx", _upx_ok, install_upx),
                              ("7zip", _sevenzip_ok, install_7zip),
                              ("die", _die_ok, install_die),
                              ("innoextract", _innoextract_ok, install_innoextract),
                              ("nuitka-extractor", _nuitka_extractor_ok, install_nuitka_extractor),
                              ("autoit-ripper", lambda: _portable_import_ok("autoit_ripper"), install_autoit_ripper),
                              ("evbunpack", lambda: _portable_import_ok("evbunpack"), install_evbunpack),
                              ("ember", _ember_ok, install_ember),
                              ("ilspy", _ilspy_ok, install_ilspy),
                              ("de4dot", _de4dot_ok, install_de4dot)):
        if name in ("floss", "capa", "upx", "7zip", "die", "innoextract",
                    "nuitka-extractor", "de4dot") and not sys.platform.startswith("win"):
            continue  # Windows-only standalone builds provisioned by this installer
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
            install_tlds()       # no-op while the cached IANA list is fresh
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


def _install_portable() -> bool:
    install_python(DEFAULT_VERSION, force=False)
    install_deps()
    if sys.platform.startswith("win"):
        install_libmagic_windows()
    return _portable_present() and _tool_deps_ok(_portable_python())


def _install_tool_deps() -> bool:
    if not _portable_present():
        return _install_portable()
    install_deps()
    if sys.platform.startswith("win"):
        install_libmagic_windows()
    return _tool_deps_ok(_portable_python())


def _install_didier() -> bool:
    install_didier()
    return _didier_present()


def _install_oms() -> bool:
    install_officemalscanner()
    return _officemalscanner_present()


def _install_ipdb() -> bool:
    return bool(install_ipdb(force=True)) and _ipdb_ok()


# One provisioning step per component, so the Diagnostics tab can retry a
# single failed install (``--component NAME``). Each returns True when the
# component is present afterwards.
COMPONENTS: dict = {
    "portable": _install_portable,
    "tool-deps": _install_tool_deps,
    "didier": _install_didier,
    "officemalscanner": _install_oms,
    "ipdb": _install_ipdb,
    "chromium": lambda: bool(install_chromium()) and _chromium_ok(),
    "vipermonkey": lambda: bool(install_vipermonkey()) and _vipermonkey_ok(),
    "webcrack": lambda: bool(install_webcrack()) and _webcrack_ok(),
    "boxps": lambda: bool(install_boxps()) and _boxps_ok(),
    "pycdc": lambda: bool(install_pycdc()) and _pycdc_ok(),
    "cfr": lambda: bool(install_cfr()) and _cfr_ok(),
    "floss": lambda: bool(install_floss()) and _floss_ok(),
    "capa": lambda: bool(install_capa()) and _capa_ok(),
    "goresym": lambda: bool(install_goresym()) and _goresym_ok(),
    "rizin": lambda: bool(install_rizin()) and _rizin_ok(),
    "upx": lambda: bool(install_upx()) and _upx_ok(),
    "7zip": lambda: bool(install_7zip()) and _sevenzip_ok(),
    "die": lambda: bool(install_die()) and _die_ok(),
    "innoextract": lambda: bool(install_innoextract()) and _innoextract_ok(),
    "nuitka-extractor": lambda: bool(install_nuitka_extractor()) and _nuitka_extractor_ok(),
    "autoit-ripper": lambda: bool(install_autoit_ripper()) and _portable_import_ok("autoit_ripper"),
    "evbunpack": lambda: bool(install_evbunpack()) and _portable_import_ok("evbunpack"),
    "ember": lambda: bool(install_ember()) and _ember_ok(),
    "ilspy": lambda: bool(install_ilspy()) and _ilspy_ok(),
    "de4dot": lambda: bool(install_de4dot()) and _de4dot_ok(),
}


def install_component(name: str) -> bool:
    """Run one component's provisioning step (clearing its 'failed' marker
    first, like a full setup does). True when it is present afterwards."""
    step = COMPONENTS.get(name)
    if step is None:
        raise SystemExit(f"Unknown component {name!r}; one of: {', '.join(COMPONENTS)}")
    _clear_mark(name)
    print(f"[>] Retrying component '{name}'")
    try:
        ok = bool(step())
    except SystemExit as exc:
        print(f"[!] Provisioning stopped: {exc}")
        ok = False
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Provisioning failed: {exc}")
        ok = False
    print(f"[+] '{name}' provisioned." if ok else f"[!] '{name}' is still not available.")
    return ok


def main() -> None:
    ap = argparse.ArgumentParser(description="Provision the portable Python runtime")
    ap.add_argument("--version", default=DEFAULT_VERSION, help="CPython X.Y (default 3.13)")
    ap.add_argument("--force", action="store_true", help="Reinstall even if present")
    ap.add_argument("--ensure", action="store_true", help="Provision only if missing (used by run.py)")
    ap.add_argument("--libmagic-only", action="store_true", help="Only provision Windows libmagic")
    ap.add_argument("--component", help="Provision only this component (used by Diagnostics → Retry)")
    args = ap.parse_args()

    if args.component:
        sys.exit(0 if install_component(args.component) else 1)

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
