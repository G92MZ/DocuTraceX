"""YARA rule engine: a rule store, a compiled ruleset and a scanner.

Rules reach the store three ways: an HTTP upload of a single ``.yar``/``.yara``
file, an HTTP upload of an archive (``.zip``/``.tar.gz``) of rule files, or the
registration of a path already on the server (a directory or file, indexed in
place so a large rule repo need not travel over HTTP).

Matching is opt-in for findings: a YARA hit is recorded and shown, but it only
becomes a *finding* (and reaches the report) when the analyst has enabled that
rule. By default nothing YARA produces is a finding.

Compilation is namespaced per source file, so a broken rule file is reported on
its own without sinking the rest. yara-python (Apache-2.0) is used in-process
when the app's interpreter has it; otherwise rule compilation/listing is
delegated to the portable Python under ``tools/`` (where the analysis runs).
"""

from __future__ import annotations

import io
import json
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from .config import settings
from .logging_config import get_logger

log = get_logger(__name__)

_RULE_EXT = (".yar", ".yara", ".rule", ".rules")
_MAX_STRINGS = 50          # matched strings kept per rule hit
_MAX_MATCH_DATA = 120      # bytes of matched data kept, hex
_SCAN_TIMEOUT = 60         # seconds per file


def _base() -> Path:
    return settings.yara_dir


def rules_dir() -> Path:
    return _base() / "rules"


def _config_path() -> Path:
    return _base() / "config.json"


def _read_config() -> dict[str, Any]:
    try:
        with _config_path().open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data.setdefault("enabled", [])
            data.setdefault("external_paths", [])
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"enabled": [], "external_paths": []}


def _write_config(cfg: dict[str, Any]) -> None:
    _base().mkdir(parents=True, exist_ok=True)
    tmp = _config_path().with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(_config_path())


def enabled_rules() -> set[str]:
    return set(_read_config().get("enabled", []))


def set_enabled(rule_names: list[str], enabled: bool) -> set[str]:
    cfg = _read_config()
    cur = set(cfg.get("enabled", []))
    if enabled:
        cur.update(rule_names)
    else:
        cur.difference_update(rule_names)
    cfg["enabled"] = sorted(cur)
    _write_config(cfg)
    return cur


# --- adding rules ------------------------------------------------------------

def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name)[:120] or "rules.yar"


def add_upload(filename: str, data: bytes) -> dict[str, Any]:
    """Add rules from an uploaded file: a single rule file or an archive."""
    rules_dir().mkdir(parents=True, exist_ok=True)
    low = filename.lower()
    added: list[str] = []
    if low.endswith((".zip",)):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for n in zf.namelist():
                if n.lower().endswith(_RULE_EXT) and not n.endswith("/"):
                    dest = rules_dir() / _safe_name(n)
                    dest.write_bytes(zf.read(n))
                    added.append(dest.name)
    elif low.endswith((".tar.gz", ".tgz", ".tar")):
        mode = "r:gz" if low.endswith((".tar.gz", ".tgz")) else "r:"
        with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tf:
            for m in tf.getmembers():
                if m.isfile() and m.name.lower().endswith(_RULE_EXT):
                    f = tf.extractfile(m)
                    if f:
                        dest = rules_dir() / _safe_name(m.name)
                        dest.write_bytes(f.read())
                        added.append(dest.name)
    else:
        dest = rules_dir() / _safe_name(filename)
        dest.write_bytes(data)
        added.append(dest.name)
    return {"added": added, "count": len(added)}


def register_path(path: str) -> dict[str, Any]:
    """Index a rule file or directory already on the server (referenced in place)."""
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")
    cfg = _read_config()
    paths = set(cfg.get("external_paths", []))
    paths.add(str(p.resolve()))
    cfg["external_paths"] = sorted(paths)
    _write_config(cfg)
    return {"registered": str(p.resolve()), "rule_files": len(list(_iter_rule_files([str(p.resolve())])))}


def unregister_path(path: str) -> None:
    cfg = _read_config()
    cfg["external_paths"] = [p for p in cfg.get("external_paths", []) if p != path]
    _write_config(cfg)


def remove_source(name: str) -> bool:
    dest = rules_dir() / _safe_name(name)
    if dest.is_file():
        dest.unlink()
        return True
    return False


def _iter_rule_files(external_paths: list[str]) -> list[Path]:
    files: list[Path] = []
    if rules_dir().is_dir():
        for p in sorted(rules_dir().iterdir()):
            if p.is_file() and p.suffix.lower() in _RULE_EXT:
                files.append(p)
    for ext in external_paths:
        ep = Path(ext)
        if ep.is_file() and ep.suffix.lower() in _RULE_EXT:
            files.append(ep)
        elif ep.is_dir():
            for p in sorted(ep.rglob("*")):
                if p.is_file() and p.suffix.lower() in _RULE_EXT:
                    files.append(p)
    return files


# --- compilation + scanning --------------------------------------------------

def _load_yara() -> tuple[Any, str | None]:
    """Import yara-python. Returns (module, None) or (None, reason).

    The rule store folder is also called ``yara/``; when yara-python is missing,
    ``import yara`` silently resolves to that folder as a namespace package, so
    the module is checked for ``compile`` instead of trusting the import.
    """
    try:
        import yara
    except Exception as exc:  # noqa: BLE001
        return None, f"yara-python not installed: {exc}"
    if not hasattr(yara, "compile"):
        where = ", ".join(str(p) for p in getattr(yara, "__path__", []) or []) or "?"
        return None, ("yara-python not installed in this interpreter "
                      f"('import yara' resolved to the folder {where})")
    return yara, None


def _portable_cmd(op: str) -> list[str] | None:
    """Command to run ``op`` of this module on the portable Python, if usable."""
    import sys

    portable = settings.portable_python()
    if not portable:
        return None
    try:
        if portable.resolve() == Path(sys.executable).resolve():
            return None
    except OSError:
        return None
    return [str(portable), "-m", "docutracex.yara_engine", op]


def _run_portable(op: str):
    """Run ``op`` on the portable, yielding each JSON line it prints."""
    import subprocess

    from . import native

    cmd = _portable_cmd(op)
    if cmd is None:
        return
    env = native.subprocess_env()
    env["DOCUTRACEX_YARA_DIR"] = str(settings.yara_dir)  # same rule store as the app
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace", env=env,
                            cwd=str(Path(__file__).resolve().parent.parent))
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if line.startswith("{"):
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
    finally:
        try:
            proc.wait(timeout=600)
        except Exception:  # noqa: BLE001
            proc.kill()
        if proc.returncode:
            err = (proc.stderr.read() if proc.stderr else "").strip()[-300:]
            log.warning("YARA on portable failed (%s): %s", proc.returncode, err)


def _delegated(op: str, fallback_error: str) -> list[dict[str, Any]]:
    events = list(_run_portable(op))
    if not events or (op == "report" and "fatal" in events[-1]):
        if _portable_cmd(op) is None:
            reason = fallback_error
        else:
            detail = events[-1]["fatal"] if events else "no output"
            reason = f"{fallback_error}; the portable Python could not run YARA either ({detail})"
        return [{"available": False, "error": reason, "errors": [], "rules": [],
                 "rule_count": 0, "file_count": 0, "fatal": reason}]
    return events


def _namespace(path: Path) -> str:
    return path.stem


def compile_rules() -> tuple[Any, dict[str, Any]]:
    """Compile every rule file (namespaced). Returns (compiled_or_None, report).

    Without yara-python in this interpreter the report comes from the portable
    and no compiled object is returned (scanning happens on the portable)."""
    yara, why = _load_yara()
    if yara is None:
        report = _delegated("report", why or "")[-1]
        report.pop("rules", None)
        report.pop("fatal", None)
        return None, report

    cfg = _read_config()
    files = _iter_rule_files(cfg.get("external_paths", []))
    report: dict[str, Any] = {"available": True, "sources": [], "rule_count": 0,
                              "errors": [], "file_count": len(files)}
    ok_files: dict[str, str] = {}
    for f in files:
        ns = _namespace(f)
        try:
            yara.compile(filepath=str(f))  # validate individually first
            # ensure unique namespace
            base_ns, i = ns, 1
            while ns in ok_files:
                ns = f"{base_ns}_{i}"; i += 1
            ok_files[ns] = str(f)
            report["sources"].append({"namespace": ns, "path": str(f), "status": "ok"})
        except Exception as exc:  # noqa: BLE001
            report["errors"].append({"path": str(f), "error": str(exc)})
            report["sources"].append({"namespace": ns, "path": str(f), "status": "error",
                                      "error": str(exc)})
    if not ok_files:
        return None, report
    try:
        compiled = yara.compile(filepaths=ok_files)
    except Exception as exc:  # noqa: BLE001
        report["errors"].append({"path": "<combined>", "error": str(exc)})
        return None, report
    # Count rules.
    try:
        report["rule_count"] = sum(1 for _ in compiled)
    except Exception:  # noqa: BLE001
        report["rule_count"] = len(ok_files)
    return compiled, report


def compile_stream():
    """Generator yielding compile progress per rule file (for NDJSON streaming)."""
    yara, why = _load_yara()
    if yara is None:
        for ev in _delegated("stream", why or ""):
            yield {"fatal": ev["fatal"]} if "fatal" in ev else ev
        return
    cfg = _read_config()
    files = _iter_rule_files(cfg.get("external_paths", []))
    yield {"total": len(files)}
    ok_files: dict[str, str] = {}
    errors: list[dict[str, Any]] = []
    for i, f in enumerate(files, 1):
        ns = _namespace(f)
        try:
            yara.compile(filepath=str(f))
            base, k = ns, 1
            while ns in ok_files:
                ns = f"{base}_{k}"; k += 1
            ok_files[ns] = str(f)
        except Exception as exc:  # noqa: BLE001
            errors.append({"path": str(f), "error": str(exc)})
        yield {"i": i, "total": len(files), "file": f.name,
               "ok": len(ok_files), "errors": len(errors)}
    rule_count = 0
    if ok_files:
        try:
            compiled = yara.compile(filepaths=ok_files)
            rule_count = sum(1 for _ in compiled)
        except Exception as exc:  # noqa: BLE001
            errors.append({"path": "<combined>", "error": str(exc)})
    yield {"done": True, "rule_count": rule_count, "file_count": len(files),
           "errors": errors, "enabled_count": len(enabled_rules())}


def list_rules() -> dict[str, Any]:
    """List known rules with their source, tags, meta and enabled flag."""
    if _load_yara()[0] is None:
        report = _delegated("report", _load_yara()[1] or "")[-1]
        report.pop("fatal", None)
        enabled = enabled_rules()
        for r in report.get("rules", []):
            r["enabled"] = r["name"] in enabled
        report["enabled_count"] = len(enabled)
        return report
    compiled, report = compile_rules()
    enabled = enabled_rules()
    rules: list[dict[str, Any]] = []
    if compiled is not None:
        for r in compiled:
            rules.append({
                "name": r.identifier,
                "namespace": getattr(r, "namespace", ""),
                "tags": list(getattr(r, "tags", []) or []),
                "meta": dict(getattr(r, "meta", {}) or {}),
                "enabled": r.identifier in enabled,
            })
    report["rules"] = rules
    report["enabled_count"] = len(enabled)
    return report


def _match_to_dict(m: Any, enabled: set[str]) -> dict[str, Any]:
    strings = []
    try:
        for s in (m.strings or [])[:_MAX_STRINGS]:
            insts = getattr(s, "instances", None)
            if insts is not None:  # yara-python >= 4.3
                for inst in insts[:3]:
                    strings.append({"id": getattr(s, "identifier", ""),
                                    "offset": inst.offset,
                                    "data": inst.matched_data[:_MAX_MATCH_DATA].hex()})
            else:  # older tuple form (offset, identifier, data)
                off, ident, data = s
                strings.append({"id": ident, "offset": off,
                                "data": bytes(data)[:_MAX_MATCH_DATA].hex()})
    except Exception:  # noqa: BLE001
        pass
    return {
        "rule": m.rule,
        "namespace": getattr(m, "namespace", ""),
        "tags": list(getattr(m, "tags", []) or []),
        "meta": dict(getattr(m, "meta", {}) or {}),
        "strings": strings,
        "enabled": m.rule in enabled,
    }


def scan_path(compiled: Any, path: Path, enabled: set[str]) -> list[dict[str, Any]]:
    if compiled is None:
        return []
    try:
        matches = compiled.match(filepath=str(path), timeout=_SCAN_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        log.warning("YARA scan failed on %s: %s", path, exc)
        return []
    return [_match_to_dict(m, enabled) for m in matches]


def _main(argv: list[str]) -> int:
    """Worker entry point run on the portable: ``-m docutracex.yara_engine OP``.

    ``report`` prints one JSON line (the list_rules report); ``stream`` prints the
    compile_stream events, one JSON line each."""
    if _load_yara()[0] is None:
        print(json.dumps({"fatal": _load_yara()[1]}), flush=True)
        return 1
    op = argv[0] if argv else "report"
    if op == "stream":
        for ev in compile_stream():
            print(json.dumps(ev), flush=True)
    else:
        print(json.dumps(list_rules(), default=str), flush=True)
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv[1:]))
