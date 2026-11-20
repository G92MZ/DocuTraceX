"""FLOSS and capa as Python libraries, run on the portable Python (a child process).

Replaces Mandiant's standalone floss.exe / capa.exe (PyInstaller builds of the same
code): same versions, same JSON output, but

- **one vivisect analysis per binary**: both tools build an analysis of the whole binary
  in memory (minutes and GB on a large one). The first run saves it (``<sample>.viv``) in
  the tools cache; FLOSS, capa, FLOSS tight on the priority functions and Deep FLOSS of
  the same binary then load it instead of analysing it again;
- nothing to download besides the Python packages and capa's rules.

Run as a script (no package import needed)::

    python vivtools.py floss|capa --cache DIR [--rules DIR] [--progress FILE] [--partial FILE] [--fast 1]
                       -- <tool arguments> <sample>

``--fast 1``: the fast analysis (no per-function emulation pass; saved apart; the
complete one is used instead when it is already saved). ``--progress``: the phase and
n / N functions, rewritten as the run goes (Tasks shows it);
``--partial``: FLOSS's strings found so far, in its JSON format (every 15 s and at the end
of each phase), so a run that hits its time limit keeps what it found.

``.viv`` files are pickles: they are only ever loaded from the tools cache, written by
this script, for a copy of the sample named by its SHA-256 (never from next to a sample).
Static analysis only: the sample is never executed.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sys
from pathlib import Path

VIV_KEEP = int(os.environ.get("DOCUTRACEX_VIV_CACHE_KEEP", "6") or 6)   # analyses kept


def _stub_binary2strings() -> None:
    """FLOSS's Rust-strings helper (binary2strings, C++) has no Windows wheel: without it,
    ``b2s_compat.py`` next to this script — the same algorithm in Python — stands in, so
    FLOSS still splits the strings of a Rust binary."""
    try:
        if os.environ.get("DOCUTRACEX_B2S_COMPAT") == "1":     # tests: the stand-in even where the module exists
            raise ImportError
        import binary2strings  # noqa: F401
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location("binary2strings", Path(__file__).with_name("b2s_compat.py"))
        if spec is None or spec.loader is None:
            return
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        sys.modules["binary2strings"] = mod


# The per-function emulation pass: ~90 % of vivisect's analysis of a large binary (34 of
# 38 min on a 6 MB x64 one). Without it the analysis is ~12x faster; FLOSS's stack strings
# stay identical, a few decoded strings / capa matches differ (some lost, some gained), so
# the app runs the fast analysis first and the complete one after, and merges both.
EMULATION_PASSES = ("vivisect.analysis.amd64.emulation", "vivisect.analysis.i386.calling")


def _fast_analysis() -> None:
    import vivisect
    orig = vivisect.VivWorkspace.analyze

    def analyze(self):  # noqa: ANN001, ANN202
        for m in EMULATION_PASSES:
            if m in self.fmodlist:
                self.delFuncAnalysisModule(m)
        return orig(self)
    vivisect.VivWorkspace.analyze = analyze


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _rm(p: Path) -> None:
    """Delete, never fail: on Windows a file still open (vivisect keeps the binary it
    analysed open in this very process) cannot be deleted — a later run cleans it up."""
    try:
        p.unlink(missing_ok=True)
    except OSError:
        pass


_PRIVATE = re.compile(r"^[0-9a-f]{64}\.\d+\.(?:fast\.)?bin(?:\.viv)?$")


def _prune(cache: Path, keep: int) -> None:
    """Keep the ``keep`` most recently used analyses (they can be hundreds of MB), and drop
    private copies a run could not delete (older than an hour: no longer in use)."""
    import time
    vivs = sorted(cache.glob("*.bin.viv"), key=lambda f: f.stat().st_mtime, reverse=True)
    vivs = [v for v in vivs if not _PRIVATE.match(v.name)]
    for v in vivs[keep:]:
        for f in (v, v.with_suffix("")):
            _rm(f)
    for f in cache.iterdir():
        try:
            if _PRIVATE.match(f.name) and time.time() - f.stat().st_mtime > 3600:
                _rm(f)
        except OSError:
            pass


class _Live:
    """Progress (``--progress``: the phase and n / N functions, read by the app while the run
    lasts, for Tasks) and partial results (``--partial``: the strings FLOSS has so far, in
    its own JSON format, so a run that hits its time limit is not lost)."""

    PHASES = {"extracting stackstrings": "stack strings", "extracting tightstrings": "tight strings",
              "decoding strings": "decoded strings"}

    def __init__(self, progress: str | None, partial: str | None) -> None:
        import threading
        self.progress, self.partial = progress, partial
        self.found: dict[str, list] = {"static_strings": [], "stack_strings": [], "tight_strings": [],
                                       "decoded_strings": []}
        self.meta: dict = {}
        self._last_p = self._last_w = 0.0
        self._lock = threading.Lock()

    def _atomic(self, path: str, text: str) -> None:
        tmp = f"{path}.tmp"
        try:
            Path(tmp).write_text(text, encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            pass

    def step(self, phase: str, done: int = 0, total: int = 0, force: bool = False) -> None:
        import json
        import time
        now = time.monotonic()
        if self.progress and (force or now - self._last_p >= 1):
            self._last_p = now
            self._atomic(self.progress, json.dumps({"phase": phase, "done": done, "total": total}))
        if self.partial and (force or now - self._last_w >= 15):
            self._last_w = now
            self.write_partial()

    def write_partial(self) -> None:
        if not self.partial:
            return
        try:
            import floss.render.json as fj
            from floss.results import Analysis, Metadata, ResultDocument
            with self._lock:
                doc = ResultDocument(metadata=Metadata(**self.meta), analysis=Analysis())
                for k, v in self.found.items():
                    setattr(doc.strings, k, list(v))
            self._atomic(self.partial, fj.render(doc))
        except Exception as exc:  # noqa: BLE001  (progress must never break the run)
            print(f"partial results not written: {exc}", file=sys.stderr)

    def hook_floss(self) -> None:
        import floss.main
        import floss.results
        import floss.utils
        live = self
        kinds = {"StackString": "stack_strings", "TightString": "tight_strings", "DecodedString": "decoded_strings"}
        log_result, get_static, load_vw = floss.results.log_result, floss.main.get_static_strings, floss.main.load_vw

        def logged(obj, *a, **k):  # noqa: ANN001, ANN002, ANN003, ANN202
            key = kinds.get(type(obj).__name__)
            if key:
                with live._lock:
                    live.found[key].append(obj)
            return log_result(obj, *a, **k)

        def statics(sample, min_length, *a, **k):  # noqa: ANN001, ANN002, ANN003, ANN202
            got = get_static(sample, min_length, *a, **k)
            live.meta = {"file_path": str(sample), "min_length": min_length}
            with live._lock:
                live.found["static_strings"] = list(got or [])
            live.step("static strings", force=True)
            return got

        def loading(*a, **k):  # noqa: ANN002, ANN003, ANN202
            live.step("loading the saved analysis" if os.environ.get("FLOSS_LOAD_VIV_WORKSPACE") == "1"
                      else "analysing the binary (vivisect)", force=True)
            return load_vw(*a, **k)

        def bar(items, disable_progress, desc="", unit=""):  # noqa: ANN001, ANN202
            items = list(items)
            phase = live.PHASES.get(desc, desc or "working")

            def gen():  # noqa: ANN202
                for i, it in enumerate(items):
                    live.step(phase, i, len(items))
                    yield it
                live.step(phase, len(items), len(items), force=True)
            return gen()

        floss.results.log_result = logged
        floss.main.get_static_strings = statics
        floss.main.load_vw = loading
        floss.utils.get_progress_bar = bar

    def hook_capa(self) -> None:
        import capa.main
        live = self
        get_ex, find = capa.main.get_extractor_from_cli, capa.main.find_capabilities

        def extractor(*a, **k):  # noqa: ANN002, ANN003, ANN202
            live.step("loading the saved analysis" if os.environ.get("CAPA_LOAD_VIV_WORKSPACE") == "1"
                      else "analysing the binary (vivisect)", force=True)
            return get_ex(*a, **k)

        def matching(*a, **k):  # noqa: ANN002, ANN003, ANN202
            live.step("matching rules", force=True)
            return find(*a, **k)
        capa.main.get_extractor_from_cli = extractor
        capa.main.find_capabilities = matching


_live: _Live | None = None


def _run(tool: str, argv: list[str]) -> int:
    if tool == "floss":
        import floss.main
        if _live is not None:
            _live.hook_floss()
        return int(floss.main.main(argv) or 0)
    import capa.main
    if _live is not None:
        _live.hook_capa()
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
    global _live
    _live = _Live(opts.get("--progress"), opts.get("--partial") if tool == "floss" else None)
    if tool == "capa":
        import floss.main                        # capa's pip package has no FLIRT signatures:
        sigs = floss.main.get_default_root() / "sigs"   # FLOSS ships the same ones
        rules = opts.get("--rules")
        if not rules or not Path(rules).is_dir():
            print("capa: rules not provisioned (tools/capa-rules)", file=sys.stderr)
            return 3
        tool_argv = ["-r", rules, "-s", str(sigs), *tool_argv]
    cache = Path(opts["--cache"]) if opts.get("--cache") else None
    fast = opts.get("--fast") == "1"
    if cache is not None and sample.is_file():
        cache.mkdir(parents=True, exist_ok=True)
        sha = _sha256(sample)
        if fast and (cache / f"{sha}.bin.viv").is_file():
            fast = False                         # the complete analysis is saved: better, and as fast to load
    if fast:
        _fast_analysis()
    if cache is None or not sample.is_file():
        return _run(tool, tool_argv)
    kind = "fast.bin" if fast else "bin"
    base = cache / f"{sha}.{kind}"
    viv = cache / f"{sha}.{kind}.viv"
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
        _rm(viv)
        os.environ["FLOSS_LOAD_VIV_WORKSPACE"] = os.environ["CAPA_LOAD_VIV_WORKSPACE"] = "0"
    # analyse, and save the analysis — on a private copy, renamed into place when complete,
    # so a run never loads a half-written one
    work = cache / f"{sha}.{os.getpid()}.{kind}"
    shutil.copyfile(sample, work)
    os.environ["FLOSS_SAVE_WORKSPACE" if tool == "floss" else "CAPA_SAVE_WORKSPACE"] = "1"
    try:
        rc = _run(tool, [*tool_argv[:-1], str(work)])
        saved = Path(f"{work}.viv")
        if rc == 0 and saved.is_file():
            if not base.is_file():
                shutil.copyfile(sample, base)
            try:
                os.replace(saved, viv)
            except OSError as exc:               # e.g. the saved one is open by another run
                print(f"analysis not saved: {exc}", file=sys.stderr)
            if kind == "bin":                    # the complete analysis supersedes the fast one
                for f in (cache / f"{sha}.fast.bin.viv", cache / f"{sha}.fast.bin"):
                    _rm(f)
            _prune(cache, VIV_KEEP)
        return rc
    finally:                                     # never turns a finished run into a failure
        _rm(work)
        _rm(Path(f"{work}.viv"))


if __name__ == "__main__":
    sys.exit(main())
