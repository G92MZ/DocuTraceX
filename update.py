#!/usr/bin/env python3
"""DocuTraceX self-updater.

Pulls the latest version from the Git remote, like the companion tools. Run it
from the application folder:

    python update.py

It is a thin, safe wrapper over Git: it never discards local changes. If you
have uncommitted edits or the branches have diverged, it stops and tells you
what to do instead of forcing anything.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(args: list[str], capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, cwd=ROOT, text=True, capture_output=capture, check=False
    )


def fail(msg: str) -> None:
    print(f"\n[!] {msg}")
    sys.exit(1)


def main() -> None:
    print("DocuTraceX updater")
    print("------------------")

    # 1. Must be a git checkout.
    if not (ROOT / ".git").exists():
        fail(
            "This folder is not a Git checkout. Get DocuTraceX with:\n"
            "    git clone https://github.com/G92MZ/DocuTraceX_pruebas.git"
        )
    if run(["git", "--version"], capture=True).returncode != 0:
        fail("Git is not installed or not on PATH. Install Git and retry.")

    # 2. Refuse to touch a dirty tree (never discard the user's local work).
    status = run(["git", "status", "--porcelain"], capture=True)
    if status.stdout.strip():
        fail(
            "You have uncommitted local changes. Commit or stash them first:\n"
            "    git stash      (set aside)   or   git checkout -- .   (discard)"
        )

    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture=True).stdout.strip()
    print(f"Current branch: {branch}")

    # 3. Fetch and compare with the remote.
    print("Fetching latest changes...")
    if run(["git", "fetch", "--quiet", "origin", branch]).returncode != 0:
        fail("Could not reach the remote. Check your connection and Git auth.")

    local = run(["git", "rev-parse", "HEAD"], capture=True).stdout.strip()
    # Ask the remote directly for the branch head — does not depend on a
    # remote-tracking ref existing locally.
    ls = run(["git", "ls-remote", "origin", f"refs/heads/{branch}"], capture=True)
    remote = ls.stdout.split("\t")[0].strip() if ls.stdout.strip() else ""
    if not remote:
        fail(f"Branch '{branch}' does not exist on the remote.")

    if local == remote:
        print("\n[=] Already up to date.")
        return

    # 4. Record what dependency-relevant files look like before updating.
    dep_files = ["pyproject.toml", "requirements.txt"]
    before = {f: _hash(ROOT / f) for f in dep_files}

    # 5. Fast-forward only — never create a merge or rewrite history.
    print("Updating...")
    pull = run(["git", "pull", "--ff-only", "origin", branch])
    if pull.returncode != 0:
        fail(
            "Could not fast-forward (branches have diverged). Resolve manually:\n"
            "    git pull --rebase    or inspect with: git log --oneline --graph"
        )

    # 6. Reinstall dependencies if they changed.
    after = {f: _hash(ROOT / f) for f in dep_files}
    if before != after:
        print("\nDependencies changed — reinstalling...")
        run([sys.executable, "-m", "pip", "install", "-e", "."])

    new = run(["git", "rev-parse", "--short", "HEAD"], capture=True).stdout.strip()
    print(f"\n[+] Updated to {new}. Done.")


def _hash(path: Path) -> str | None:
    try:
        return str(path.stat().st_mtime_ns) + ":" + str(path.stat().st_size)
    except OSError:
        return None


if __name__ == "__main__":
    main()
