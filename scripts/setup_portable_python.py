#!/usr/bin/env python3
"""Provision the portable Python runtime under ``tools/`` and its dependencies.

Downloads a python-build-standalone CPython build (Astral) for this platform,
extracts it to ``tools/python/``, installs the app and its dependencies into it
(so DocuTraceX runs on the bundled interpreter), and on Windows also provisions
the native libmagic (DLL + magic database) under ``tools/libmagic/``.

Primary version: CPython 3.13 (broadest wheel coverage today; matches the
roadmap). Add a second version later only if a specific tool needs it.

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
    print("[>] Installing DocuTraceX and dependencies into the portable interpreter")
    subprocess.run([str(py), "-m", "pip", "install", "-e", str(ROOT)], check=True)


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
            if _tool_deps_ok(py):
                print(f"[=] Portable Python present with tool deps OK at {PY_DIR}")
                return True
            print("[>] Portable present but tool dependencies missing — updating...")
            install_deps()
            if sys.platform.startswith("win"):
                install_libmagic_windows()
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
