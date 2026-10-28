#!/usr/bin/env python3
"""Self-updater for DocuTraceX.

Checks GitHub for a newer version and, if there is one, downloads the latest
code from the default branch and updates the app files in place — no git
required, using only the Python standard library (works on Windows and Linux).

Your data is preserved: cases (``cases/``), the provisioned portable runtime and
external tools (``tools/``), your YARA rules (``yara/``) and your settings
(``config/``) are never overwritten.

  python update.py            # check, then ask before updating
  python update.py --check    # only check, change nothing
  python update.py --yes      # update without asking

Private repo? Set a token in the environment first:
  GITHUB_TOKEN=ghp_xxx python update.py
"""
from __future__ import annotations

import argparse
import io
import os
import shutil
import sys
import tempfile
import urllib.request
import zipfile

OWNER = "G92MZ"
REPO = "DocuTraceX"
BRANCH = "main"

# Top-level folders that are NEVER overwritten (your data + expensive runtime).
PROTECTED = {"cases", "tools", "yara", "config"}

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def _request(url: str, accept: str | None = None):
    headers = {"User-Agent": f"{REPO}-updater"}
    if accept:
        headers["Accept"] = accept
    if TOKEN:
        headers["Authorization"] = f"token {TOKEN}"
    return urllib.request.Request(url, headers=headers)


def _get(url: str, accept: str | None = None, timeout: int = 60) -> bytes:
    with urllib.request.urlopen(_request(url, accept), timeout=timeout) as r:
        return r.read()


def local_version() -> str:
    try:
        with open(os.path.join(HERE, "VERSION"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "0.0.0"


def remote_version() -> str:
    # Prefer the GitHub API: it reflects a fresh push immediately, whereas
    # raw.githubusercontent.com serves a CDN-cached copy for a few minutes.
    api = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/VERSION?ref={BRANCH}"
    try:
        return _get(api, accept="application/vnd.github.raw").decode("utf-8", "replace").strip()
    except Exception:  # noqa: BLE001  (rate limit / offline -> fall back to raw)
        raw = f"https://raw.githubusercontent.com/{OWNER}/{REPO}/{BRANCH}/VERSION"
        return _get(raw).decode("utf-8", "replace").strip()


def _vtuple(v: str) -> tuple:
    out = []
    for part in v.strip().lstrip("vV").replace("-", ".").split("."):
        out.append(int(part) if part.isdigit() else 0)
    return tuple(out)


def is_newer(remote: str, local: str) -> bool:
    return _vtuple(remote) > _vtuple(local)


def _download_zip() -> bytes:
    if TOKEN:
        url = f"https://api.github.com/repos/{OWNER}/{REPO}/zipball/{BRANCH}"
    else:
        url = f"https://github.com/{OWNER}/{REPO}/archive/refs/heads/{BRANCH}.zip"
    return _get(url, timeout=180)


def apply_update() -> int:
    """Download the latest code and copy it over the install dir. Returns the
    number of files written. Protected data folders are left untouched.

    ``VERSION`` is written LAST and only if every other file was copied: a file
    that cannot be replaced (e.g. ``samples/samples.zip`` open in WinRAR/7-Zip,
    or locked by an antivirus scan) must not leave a half-updated install that
    already claims the new version — the next run would say "up to date" and
    never retry. Locked files are reported and the update can simply be re-run."""
    zf = zipfile.ZipFile(io.BytesIO(_download_zip()))
    names = [n for n in zf.namelist() if n.strip()]
    if not names:
        raise RuntimeError("empty archive")
    root = names[0].split("/")[0]          # e.g. "DocuTraceX-main" or a commit hash
    tmp = tempfile.mkdtemp(prefix=f"{REPO}_upd_")
    try:
        zf.extractall(tmp)
        src = os.path.join(tmp, root)
        copied = 0
        failed: list[str] = []
        version_src = None
        for dirpath, dirnames, filenames in os.walk(src):
            rel = os.path.relpath(dirpath, src)
            top = "" if rel == "." else rel.split(os.sep)[0]
            if top in PROTECTED:
                dirnames[:] = []
                continue
            dest_dir = HERE if rel == "." else os.path.join(HERE, rel)
            os.makedirs(dest_dir, exist_ok=True)
            for fn in filenames:
                s_path = os.path.join(dirpath, fn)
                if rel == "." and fn == "VERSION":
                    version_src = s_path          # written at the very end
                    continue
                try:
                    shutil.copy2(s_path, os.path.join(dest_dir, fn))
                    copied += 1
                except OSError as exc:
                    failed.append(f"{os.path.join(rel, fn) if rel != '.' else fn}: {exc.strerror or exc}")
        if failed:
            raise RuntimeError(
                f"{len(failed)} file(s) could not be replaced — close any program using them "
                "(an archive viewer, an editor, the running app) and run the update again:\n  "
                + "\n  ".join(failed[:20]))
        if version_src:
            shutil.copy2(version_src, os.path.join(HERE, "VERSION"))
            copied += 1
        return copied
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _remove_loose_samples() -> list[str]:
    """Since 1.11 the samples ship encrypted in samples/samples.zip (password
    "infected") so antivirus engines leave them alone. Remove the copies that
    older versions shipped unpacked (sample.<ext> and lab/phish_lab.eml);
    ``python scripts/make_samples.py --extract`` brings them back."""
    base = os.path.join(HERE, "samples")
    if not os.path.isfile(os.path.join(base, "samples.zip")):
        return []
    removed = []
    for fn in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        if fn.startswith("sample.") and os.path.isfile(os.path.join(base, fn)):
            os.remove(os.path.join(base, fn))
            removed.append(fn)
    lab = os.path.join(base, "lab", "phish_lab.eml")
    if os.path.isfile(lab):
        os.remove(lab)
        removed.append("lab/phish_lab.eml")
    return removed


def main() -> None:
    ap = argparse.ArgumentParser(prog="update.py", description=f"Update {REPO} to the latest version.")
    ap.add_argument("--check", action="store_true", help="only check, do not change anything")
    ap.add_argument("--yes", "-y", action="store_true", help="update without asking")
    args = ap.parse_args()

    # Exit codes (consumed by run.py's auto-update flow):
    #   0 = already up to date, or the user cancelled (nothing changed)
    #   1 = error (could not check, or the update failed)
    #   2 = updated successfully
    loc = local_version()
    try:
        rem = remote_version()
    except Exception as e:  # noqa: BLE001
        print(f"Could not check for updates: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Installed: {loc}   Latest: {rem}")
    if not is_newer(rem, loc):
        print("Already up to date.")
        return
    if args.check:
        print("An update is available. Run without --check to install.")
        return
    if not args.yes:
        ans = input(f"Update {loc} -> {rem}? [y/N] ").strip().lower()
        if ans not in ("y", "yes", "s", "si", "sí"):
            print("Cancelled.")
            return
    # rev: bhd1Sl5iFX
    try:
        n = apply_update()
    except Exception as e:  # noqa: BLE001
        print(f"Update failed: {e}", file=sys.stderr)
        sys.exit(1)
    # ref: gmzpt
    gone = _remove_loose_samples()
    if gone:
        print(f"Removed {len(gone)} unpacked sample(s): they now live in samples/samples.zip "
              "(password 'infected'); unpack with: python scripts/make_samples.py --extract")
    print(f"Updated to {rem} ({n} files).")
    sys.exit(2)   # signal "updated" so run.py re-provisions the toolchain


if __name__ == "__main__":
    main()
