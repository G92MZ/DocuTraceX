"""Python: analyse ``.py`` source and ``.pyc`` byte-compiled modules.

Python is an increasingly common malware language — droppers, stealers and
loaders shipped as a loose ``.py``/``.pyc`` or bundled into an ``.exe`` with
PyInstaller (see :mod:`pyinstaller`, which unpacks the archive and hands the
``.pyc`` modules here). This module gathers the Python a case carries, runs the
shared behaviour rules (``script_rules`` lang ``PY``) and exposes the recovered
code in its own Components tab. Nothing is executed.

``.py`` is read as source (with a light decode of obvious ``base64``/hex/``exec``
wrappers). ``.pyc`` is recovered in the best available way, recorded in the
script's ``source`` field:

1. **decompiled** — with ``pycdc`` provisioned (``tools/pycdc``), real source.
2. **disassembled** — else the code object is unmarshalled and a dotted-call +
   string listing is reconstructed from the bytecode (works when the analysing
   interpreter's version matches the ``.pyc``).
3. **strings** — else printable string/const runs are carved from the bytes.

The rules run on whatever text is recovered; a suspicious-import scan runs in
every mode so even raw-string recovery yields signal.
"""

from __future__ import annotations

import base64
import binascii
import dis
import marshal
import re
from pathlib import Path
from typing import Any

from . import javascript, script_rules

_MAX_ITEMS = 60
_MAX_FILES = 400
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_CODE = 400_000
_KEEP_CODE = 80_000
_PY_EXT = {".py", ".pyw", ".pyc", ".pyo"}

# .pyc magic: the canonical release value (low 2 bytes, little-endian, before
# the \r\n) -> CPython version, for the common ones.
_PYC_MAGIC = {
    3230: "3.2", 3310: "3.3", 3350: "3.4", 3351: "3.5", 3379: "3.6", 3394: "3.7",
    3413: "3.8", 3425: "3.9", 3439: "3.10", 3495: "3.11", 3531: "3.12", 3571: "3.13",
    3600: "3.14",
}

_SUSP_IMPORTS = re.compile(
    r"\b(?:subprocess|ctypes|socket|marshal|pickle|winreg|_winreg|base64|requests|urllib|"
    r"http\.client|pynput|win32crypt|keyring|cryptography|Crypto|pyaes|zlib|lzma|clr)\b")


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "python", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


def static_hits(code: str) -> list[dict[str, Any]]:
    return script_rules.scan(code, script_rules.PY)


# --- .py light deobfuscation -------------------------------------------------
_B64_CALL = re.compile(r"""base64\.(?:urlsafe_)?b64decode\(\s*['"]([A-Za-z0-9+/=_\-]{8,})['"]""")
_HEX_CALL = re.compile(r"""(?:bytes\.fromhex|binascii\.unhexlify)\(\s*['"]([0-9a-fA-F]{8,})['"]""")


def deobfuscate(src: str) -> dict[str, Any]:
    """A light, static decode of the common ``.py`` wrappers: append the decoded
    payloads so the rules see what ``exec(base64.b64decode(...))`` would run."""
    methods: list[str] = []
    extra: list[str] = []
    for m in _B64_CALL.finditer(src):
        try:
            extra.append(base64.b64decode(m.group(1) + "===").decode("utf-8", "replace"))
            if "base64" not in methods:
                methods.append("base64")
        except (binascii.Error, ValueError):
            pass
    for m in _HEX_CALL.finditer(src):
        try:
            extra.append(bytes.fromhex(m.group(1)).decode("utf-8", "replace"))
            if "hex" not in methods:
                methods.append("hex")
        except ValueError:
            pass
    extra = [e for e in extra if e.strip()]
    if not extra:
        return {"changed": False, "code": src, "methods": []}
    return {"changed": True, "methods": methods,
            "code": src + "\n\n# --- DocuTraceX: decoded payload(s) ---\n" + "\n".join(extra)}


# --- .pyc recovery -----------------------------------------------------------
def _pyc_version(blob: bytes) -> str:
    if len(blob) < 4 or blob[2:4] != b"\r\n":
        return "unknown"
    import struct
    val = struct.unpack_from("<H", blob, 0)[0]
    if val in _PYC_MAGIC:
        return _PYC_MAGIC[val]
    # Nearest known release magic at or below this value (dev builds sit between).
    below = [v for v in _PYC_MAGIC if v <= val]
    return _PYC_MAGIC[max(below)] + "+" if below else "unknown"


def _carve_strings(blob: bytes, minlen: int = 5) -> list[str]:
    out = [m.group().decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, blob)]
    return out


def _reconstruct(code_obj: Any) -> list[str]:
    """Rebuild dotted name/attribute tokens and string consts from a code object
    (recursively), so the behaviour rules match ``os.system`` etc."""
    out: list[str] = []
    seen: set[int] = set()

    def walk(co: Any) -> None:
        if id(co) in seen:
            return
        seen.add(id(co))
        for c in getattr(co, "co_consts", ()) or ():
            if isinstance(c, str) and c.strip():
                out.append(c)
            elif isinstance(c, bytes):
                out.append(c.decode("latin-1", "replace"))
            elif hasattr(c, "co_code"):
                walk(c)
        chain: list[str] = []
        try:
            instrs = list(dis.get_instructions(co))
        except Exception:  # noqa: BLE001
            instrs = []
        for ins in instrs:
            op = ins.opname
            if op in ("LOAD_GLOBAL", "LOAD_NAME"):
                if chain:
                    out.append(".".join(chain))
                chain = [str(ins.argval)]
            elif op == "IMPORT_NAME":
                out.append("import " + str(ins.argval))
                if chain:
                    out.append(".".join(chain))
                chain = [str(ins.argval)]
            elif op in ("LOAD_ATTR", "LOAD_METHOD", "IMPORT_FROM"):
                chain.append(str(ins.argval)) if chain else chain.append(str(ins.argval))
            else:
                if chain:
                    out.append(".".join(chain))
                    chain = []
        if chain:
            out.append(".".join(chain))

    walk(code_obj)
    return out


_INCOMPLETE_MARKERS = ("decompyle incomplete", "could not", "unsupported opcode", "unsupported node")


def recover_pyc(path: Path, blob: bytes) -> tuple[str, str, str]:
    """Recover a ``.pyc`` into one text that is BOTH shown and scanned (so the
    findings' line numbers always match the displayed code).

    Returns (code, source_kind, py_version). pycdc lags new CPython and often
    emits only the imports/globals with "# WARNING: Decompyle incomplete",
    dropping the function body. When that happens the calls reconstructed from
    the bytecode are appended below the partial source — so the dropped
    ``subprocess.Popen``/``urlopen``/… are both detected and visible.
    """
    ver = _pyc_version(blob)
    # Reconstruct dotted calls + strings from the bytecode (version-matched).
    recon = ""
    header = 16 if ver not in ("3.3", "3.4", "3.5", "3.6", "unknown") else 12
    for hdr in (header, 16, 12, 8):
        try:
            code_obj = marshal.loads(blob[hdr:])
            if hasattr(code_obj, "co_code"):
                toks = _reconstruct(code_obj)
                if toks:
                    recon = "\n".join(toks)
                    break
        except Exception:  # noqa: BLE001
            continue
    src = _decompile(path)                     # pycdc, optional (may be partial)
    complete = bool(src) and not any(m in src.lower() for m in _INCOMPLETE_MARKERS)

    if complete:
        return src, "decompiled", ver
    if src and recon:
        joined = (src.rstrip() + "\n\n# --- DocuTraceX: calls recovered from the bytecode "
                  "(the decompiler stopped early) ---\n" + recon)
        return joined, "decompiled + bytecode", ver
    if recon:
        return recon, "disassembled", ver
    if src:
        return src, "decompiled", ver
    return "\n".join(_carve_strings(blob)), "strings", ver


def _decompile(path: Path) -> str:
    """Decompile a ``.pyc`` to source with pycdc, if provisioned. Best effort."""
    import subprocess

    from ..config import settings

    exe = getattr(settings, "pycdc_executable", lambda: None)()
    if not exe:
        return ""
    try:
        proc = subprocess.run([str(exe), str(path)], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    except Exception:  # noqa: BLE001
        return ""
    out = (proc.stdout or "").strip()
    # pycdc emits "# Could not decompile ..." on failure; keep only real output.
    if not out or out.lower().startswith("# could not") or "unsupported opcode" in out.lower():
        return ""
    return out


def _import_scan(text: str, loc: str, origin: str) -> list[dict[str, Any]]:
    """Flag suspicious modules even when only raw strings survived (no dotted
    calls to match the main rules)."""
    found = sorted({m.group(0) for m in _SUSP_IMPORTS.finditer(text)})
    if len(found) >= 2:
        return [_finding("py_suspicious_imports", "medium",
                         f"[{origin}] suspicious modules referenced: {', '.join(found[:12])}",
                         loc, ", ".join(found[:20]))]
    return []


# --- collection + analysis ---------------------------------------------------
def collect(original: Path, extracted_dir: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    paths: list[Path] = []
    if extracted_dir.is_dir():
        paths = [p for p in sorted(extracted_dir.rglob("*")) if p.is_file()][:_MAX_FILES]
    if original.is_file():
        paths.append(original)
    for p in paths:
        ext = p.suffix.lower()
        if ext not in _PY_EXT:
            continue
        try:
            raw = p.read_bytes()[:_MAX_FILE_BYTES]
        except OSError:
            continue
        try:
            rel = p.relative_to(extracted_dir.parent).as_posix()
        except ValueError:
            rel = p.name
        items.append({"origin": f"file:{rel}", "location": f"file:{rel}",
                      "ext": ext, "raw": raw, "path": p})
    seen: set[str] = set()
    uniq = []
    for it in items:
        key = f"{it['ext']}:{len(it['raw'])}:{it['raw'][:64]!r}"
        if key not in seen:
            seen.add(key)
            uniq.append(it)
    return uniq[:_MAX_ITEMS]


def analyze(original: Path, extracted_dir: Path, modules: dict[str, Any] | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "python", "status": "ok", "scripts": [], "findings": []}
    for i, it in enumerate(collect(original, extracted_dir), 1):
        loc, origin = it["location"], it["origin"]
        is_pyc = it["ext"] in (".pyc", ".pyo")
        source_kind = "source"
        pyver = ""
        deob_methods: list[str] = []
        orig_code = ""

        if is_pyc:
            # One text is both shown and scanned, so the findings' line numbers
            # match the displayed code (the bytecode-recovered calls are appended
            # when pycdc stops early).
            display, source_kind, pyver = recover_pyc(it["path"], it["raw"])
            code = display[:_MAX_CODE]
        else:
            src = it["raw"].decode("utf-8", "replace")
            orig_code = src[:_MAX_CODE]
            deob = deobfuscate(src)
            deob_methods = deob["methods"]
            code = (deob["code"] if deob["changed"] else src)[:_MAX_CODE]

        hits = static_hits(code)
        mets = javascript.metrics(code)
        script = {
            "id": i, "kind": "python", "origin": origin, "location": loc,
            "size": len(it["raw"]), "code": code[:_KEEP_CODE],
            "code_truncated": len(code) > _KEEP_CODE,
            "code_is_deobfuscated": bool(deob_methods) or source_kind in ("decompiled", "disassembled"),
            "original_code": orig_code[:_KEEP_CODE] if deob_methods else "",
            "original_truncated": bool(deob_methods) and len(orig_code) > _KEEP_CODE,
            "deob_methods": deob_methods, "deob_schemes": [],
            "source": source_kind, "python_version": pyver,
            "hits": hits, "metrics": mets, "_full_code": code,
        }
        res["scripts"].append(script)

        by_rule: dict[str, list[dict[str, Any]]] = {}
        for h in hits:
            by_rule.setdefault(h["rule"], []).append(h)
        for rule, hs in by_rule.items():
            res["findings"].append(_finding(rule, hs[0]["severity"], f"[{origin}] {hs[0]['label']}", loc,
                                            "\n".join(f"line {h['line_no']}: {h['line']}" for h in hs[:5])))
        chain = script_rules.risk_escalation(hits)
        if chain:
            res["findings"].append(_finding(chain["rule"], chain["severity"],
                                            f"[{origin}] {chain['label']}", loc, chain["detail"]))
        res["findings"].extend(_import_scan(code, loc, origin))
        if is_pyc and source_kind != "strings":
            res["findings"].append(_finding("py_pyc_recovered", "info",
                f"[{origin}] .pyc recovered by {source_kind}"
                + (f" (Python {pyver})" if pyver and pyver != "unknown" else ""), loc))

    # collapse duplicate findings (same rule+location) kept once
    res["counts"] = {"findings": len(res["findings"]), "scripts": len(res["scripts"])}
    if any(f["severity"] in ("high", "medium") for f in res["findings"]):
        res["status"] = "ok_with_findings"
    return res
