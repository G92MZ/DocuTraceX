"""FLOSS and capa as Python libraries, run on the portable Python (a child process).

Replaces Mandiant's standalone floss.exe / capa.exe (PyInstaller builds of the same
code): same versions, same JSON output, but

- **one vivisect analysis per binary**: both tools build an analysis of the whole binary
  in memory (minutes and GB on a large one). The first run saves it (``<sample>.viv``) in
  the tools cache; FLOSS, capa, FLOSS tight on the priority functions and Deep FLOSS of
  the same binary then load it instead of analysing it again;
- nothing to download besides the Python packages and capa's rules.

Run as a script (no package import needed)::

    python vivtools.py floss|capa --cache DIR [--rules DIR] -- <tool arguments> <sample>

``.viv`` files are pickles: they are only ever loaded from the tools cache, written by
this script, for a copy of the sample named by its SHA-256 (never from next to a sample).
Static analysis only: the sample is never executed.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import types
from pathlib import Path

VIV_KEEP = int(os.environ.get("DOCUTRACEX_VIV_CACHE_KEEP", "6") or 6)   # analyses kept


def _stub_binary2strings() -> None:
    """FLOSS's Rust-strings helper has no Windows wheel (it needs a C++ compiler). Without
    it, Rust string extraction fails with a ``language_strings`` error: the caller retries
    with ``--language none`` (the rest of FLOSS is unaffected)."""
    try:
        import binary2strings  # noqa: F401
    except ImportError:
        def missing(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
            raise RuntimeError("language_strings: binary2strings is not installed (Rust strings)")
        mod = types.ModuleType("binary2strings")
        mod.extract_all_strings = missing
        mod.extract_string = missing
        sys.modules["binary2strings"] = mod


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _prune(cache: Path, keep: int) -> None:
    """Keep the ``keep`` most recently used analyses (they can be hundreds of MB)."""
    vivs = sorted(cache.glob("*.bin.viv"), key=lambda f: f.stat().st_mtime, reverse=True)
    for v in vivs[keep:]:
        for f in (v, v.with_suffix("")):
            f.unlink(missing_ok=True)


def _run(tool: str, argv: list[str]) -> int:
    if tool == "floss":
        import floss.main
        return int(floss.main.main(argv) or 0)
    import capa.main
    return int(capa.main.main(argv) or 0)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in argv or not argv or argv[0] not in ("floss", "capa"):
        print(__doc__, file=sys.stderr)
        return 2
    sep = argv.index("--")
    own, tool_argv = argv[1:sep], argv[sep + 1:]
    opts = dict(zip(own[::2], own[1::2]))
    sample = Path(tool_argv[-1])
    tool = argv[0]
    _stub_binary2strings()
    if tool == "capa":
        import floss.main                        # capa's pip package has no FLIRT signatures:
        sigs = floss.main.get_default_root() / "sigs"   # FLOSS ships the same ones
        rules = opts.get("--rules")
        if not rules or not Path(rules).is_dir():
            print("capa: rules not provisioned (tools/capa-rules)", file=sys.stderr)
            return 3
        tool_argv = ["-r", rules, "-s", str(sigs), *tool_argv]
    cache = Path(opts["--cache"]) if opts.get("--cache") else None
    if cache is None or not sample.is_file():
        return _run(tool, tool_argv)
    cache.mkdir(parents=True, exist_ok=True)
    sha = _sha256(sample)
    base = cache / f"{sha}.bin"
    viv = cache / f"{sha}.bin.viv"
    for k in ("FLOSS_SAVE_WORKSPACE", "CAPA_SAVE_WORKSPACE", "FLOSS_LOAD_VIV_WORKSPACE", "CAPA_LOAD_VIV_WORKSPACE"):
        os.environ[k] = "0"
    if viv.is_file():
        # the saved analysis: loaded instead of analysing the binary again
        if not base.is_file():
            shutil.copyfile(sample, base)
        os.environ["FLOSS_LOAD_VIV_WORKSPACE" if tool == "floss" else "CAPA_LOAD_VIV_WORKSPACE"] = "1"
        os.utime(viv)
        try:
            rc = _run(tool, [*tool_argv[:-1], str(base)])
        except Exception as exc:  # noqa: BLE001  (e.g. saved by another vivisect version)
            print(f"saved analysis unusable ({exc}): analysing again", file=sys.stderr)
            rc = -1
        if rc == 0:
            return 0
        viv.unlink(missing_ok=True)
        os.environ["FLOSS_LOAD_VIV_WORKSPACE"] = os.environ["CAPA_LOAD_VIV_WORKSPACE"] = "0"
    # analyse, and save the analysis — on a private copy, renamed into place when complete,
    # so a run never loads a half-written one
    work = cache / f"{sha}.{os.getpid()}.bin"
    shutil.copyfile(sample, work)
    os.environ["FLOSS_SAVE_WORKSPACE" if tool == "floss" else "CAPA_SAVE_WORKSPACE"] = "1"
    try:
        rc = _run(tool, [*tool_argv[:-1], str(work)])
        saved = Path(f"{work}.viv")
        if rc == 0 and saved.is_file():
            if not base.is_file():
                shutil.copyfile(sample, base)
            os.replace(saved, viv)
            _prune(cache, VIV_KEEP)
        return rc
    finally:
        work.unlink(missing_ok=True)
        Path(f"{work}.viv").unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
