"""Java archives and class files: ``.jar`` / ``.war`` / ``.ear`` and loose
``.class`` / ``.jsp``.

A ``.jar``/``.war`` is a ZIP, so extraction and recursion are handled by the
archive/nested machinery; this module adds the Java-specific understanding:

- **MANIFEST.MF** — ``Main-Class`` (entry point), ``Premain-Class`` /
  ``Launcher-Agent-Class`` (a Java agent), ``Class-Path``, ``Add-Opens``.
- **.class** — the constant pool is parsed (``struct``) and the referenced
  classes/methods and string literals are matched against the shared behaviour
  rules (``script_rules`` lang ``JAVA``): ``Runtime.exec``/``ProcessBuilder``,
  ``URL``/``Socket``, reflection/``defineClass``, ``ScriptEngine``, JNDI
  (Log4Shell), deserialization gadgets, ``Base64``/crypto. With **CFR**
  provisioned (and a JVM), interesting classes are decompiled to real source.
- **JSP** — scriptlet text is scanned for webshell patterns
  (``request.getParameter`` → ``Runtime.exec``).
- **web.xml** — servlet/filter mappings. **Signing** — the presence and signer
  of ``META-INF/*.SF`` + ``*.RSA``. **Serialized objects** — the ``AC ED 00 05``
  stream magic (deserialization payloads).

Nothing is executed; CFR only decompiles, in a separate process.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from . import javascript, script_rules
from ..config import tmo

_MAX_CLASSES = 600
_MAX_DECOMPILE = 40
_MAX_ITEMS = 60
_MAX_FILE_BYTES = 8 * 1024 * 1024
_KEEP_CODE = 80_000
_CLASS_MAGIC = b"\xca\xfe\xba\xbe"
_SER_MAGIC = b"\xac\xed\x00\x05"
_JAR_EXT = {".jar", ".war", ".ear"}
_JSP_EXT = {".jsp", ".jspx", ".jspf"}


def _finding(rule: str, severity: str, detail: str, location: str, evidence: str = "") -> dict:
    return {"tool": "java", "rule": rule, "severity": severity, "detail": detail,
            "location": location, "evidence": evidence[:2000]}


# --- .class constant pool ----------------------------------------------------
def parse_class(blob: bytes) -> dict[str, Any]:
    """Parse a .class constant pool: return {this, strings, refs}. Robust to a
    truncated tail — only the pool is needed for triage."""
    out: dict[str, Any] = {"this": "", "strings": [], "refs": []}
    if blob[:4] != _CLASS_MAGIC or len(blob) < 10:
        return out
    cp_count = struct.unpack_from(">H", blob, 8)[0]
    pos = 10
    entries: dict[int, tuple] = {}
    i = 1
    try:
        while i < cp_count:
            tag = blob[pos]
            pos += 1
            if tag == 1:  # Utf8
                ln = struct.unpack_from(">H", blob, pos)[0]
                pos += 2
                entries[i] = ("utf8", blob[pos:pos + ln].decode("utf-8", "replace"))
                pos += ln
            elif tag in (7, 8, 16, 19, 20):      # Class/String/MethodType/Module/Package: u2
                entries[i] = ("ref1", struct.unpack_from(">H", blob, pos)[0])
                pos += 2
            elif tag in (9, 10, 11, 12, 17, 18):  # Fieldref/Methodref/IfaceMethodref/NameAndType/Dynamic: u2 u2
                entries[i] = ("ref2", struct.unpack_from(">HH", blob, pos))
                pos += 4
            elif tag == 15:                       # MethodHandle: u1 u2
                entries[i] = ("mh", None)
                pos += 3
            elif tag in (3, 4):                   # Integer/Float
                pos += 4
            elif tag in (5, 6):                   # Long/Double: two slots
                pos += 8
                i += 1
            else:
                break
            i += 1
    except (IndexError, struct.error):
        pass

    def utf(idx: int) -> str:
        e = entries.get(idx)
        return e[1] if e and e[0] == "utf8" else ""

    def class_name(idx: int) -> str:
        e = entries.get(idx)
        return utf(e[1]) if e and e[0] == "ref1" else ""

    strings = [v for (t, v) in entries.values() if t == "utf8" and isinstance(v, str)]
    refs: list[str] = []
    for t, v in entries.values():
        if t == "ref2" and isinstance(v, tuple):          # Fieldref/Methodref/...
            ci, nti = v
            cn = class_name(ci)
            nt = entries.get(nti)
            mn = utf(nt[1][0]) if nt and nt[0] == "ref2" and isinstance(nt[1], tuple) else ""
            if cn or mn:
                refs.append(f"{cn}.{mn}" if mn else cn)
    out["strings"] = strings
    out["refs"] = sorted(set(refs))
    return out


def class_text(parsed: dict[str, Any]) -> str:
    return "\n".join(parsed.get("refs", []) + parsed.get("strings", []))


def _decompile(path: Path) -> str:
    """Decompile a .class with CFR (needs a JVM + the CFR jar). Best effort."""
    import subprocess

    from ..config import settings

    jar = getattr(settings, "cfr_jar", lambda: None)()
    java = getattr(settings, "java_executable", lambda: None)()
    if not jar or not java:
        return ""
    try:
        proc = subprocess.run([str(java), "-jar", str(jar), str(path), "--silent", "true"],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=tmo(60))
    except Exception:  # noqa: BLE001
        return ""
    out = (proc.stdout or "").strip()
    return out if out and "class" in out else ""


def scan_class(path: Path, blob: bytes, loc: str, budget: list[int] | None = None) -> tuple[list[dict], dict]:
    parsed = parse_class(blob)
    cp_text = class_text(parsed)
    cp_hits = script_rules.scan(cp_text, script_rules.JAVA)
    # Decompile with CFR only classes that already look suspicious (and within a
    # budget), so a fat jar does not fire hundreds of JVM subprocesses.
    deco = ""
    if cp_hits and (budget is None or budget[0] > 0):
        deco = _decompile(path)
        if deco and budget is not None:
            budget[0] -= 1
    code = deco or cp_text
    # Always keep the constant-pool hits (decompiled source may drop references
    # the pool still carries); add the decompiled source's hits on top.
    hits = cp_hits if not deco else script_rules.scan(cp_text + "\n" + deco, script_rules.JAVA)
    findings: list[dict] = []
    by_rule: dict[str, list] = {}
    for h in hits:
        by_rule.setdefault(h["rule"], []).append(h)
    for rule, hs in by_rule.items():
        findings.append(_finding(rule, hs[0]["severity"], f"[{loc}] {hs[0]['label']}", loc,
                                 "\n".join(f"{h['line']}" for h in hs[:4])))
    chain = script_rules.risk_escalation(hits)
    if chain:
        findings.append(_finding(chain["rule"], chain["severity"], f"[{loc}] {chain['label']}", loc, chain["detail"]))
    script = {"kind": "java", "origin": loc, "location": loc, "source": "decompiled" if deco else "constant-pool",
              "this_class": parsed.get("this", ""), "size": len(blob),
              "code": code[:_KEEP_CODE], "code_truncated": len(code) > _KEEP_CODE,
              "code_is_deobfuscated": bool(deco), "original_code": "", "deob_methods": [],
              "hits": hits, "metrics": javascript.metrics(code), "_full_code": code}
    return findings, script


def scan_jsp(text: str, loc: str) -> tuple[list[dict], dict]:
    hits = script_rules.scan(text, script_rules.JAVA)
    findings: list[dict] = []
    by_rule: dict[str, list] = {}
    for h in hits:
        by_rule.setdefault(h["rule"], []).append(h)
    for rule, hs in by_rule.items():
        findings.append(_finding(rule, hs[0]["severity"], f"[{loc}] {hs[0]['label']}", loc,
                                 "\n".join(f"line {h['line_no']}: {h['line']}" for h in hs[:4])))
    chain = script_rules.risk_escalation(hits)
    if chain:
        findings.append(_finding(chain["rule"], chain["severity"], f"[{loc}] {chain['label']}", loc, chain["detail"]))
    script = {"kind": "jsp", "origin": loc, "location": loc, "source": "source",
              "size": len(text), "code": text[:_KEEP_CODE], "code_truncated": len(text) > _KEEP_CODE,
              "code_is_deobfuscated": False, "original_code": "", "deob_methods": [],
              "hits": hits, "metrics": javascript.metrics(text), "_full_code": text}
    return findings, script


# --- manifest / web.xml / signing -------------------------------------------
def parse_manifest(text: str) -> dict[str, str]:
    """MF key: value, with continuation lines (leading space)."""
    out: dict[str, str] = {}
    key = ""
    for raw in text.splitlines():
        if raw.startswith(" ") and key:
            out[key] += raw[1:]
        elif ":" in raw:
            k, _, v = raw.partition(":")
            key = k.strip()
            out[key] = v.strip()
    return out


_MF_RISKY = {
    "Premain-Class": ("java_agent", "high", "declares a Java agent (Premain-Class)"),
    "Launcher-Agent-Class": ("java_agent", "high", "declares a launcher Java agent"),
    "Agent-Class": ("java_agent", "high", "declares a Java agent (Agent-Class)"),
}


def manifest_findings(mf: dict[str, str], loc: str) -> list[dict]:
    out: list[dict] = []
    if mf.get("Main-Class"):
        out.append(_finding("java_main_class", "info", f"executable jar — Main-Class {mf['Main-Class']}",
                            loc, mf["Main-Class"]))
    for k, (rule, sev, label) in _MF_RISKY.items():
        if mf.get(k):
            out.append(_finding(rule, sev, f"{label}: {mf[k]}", loc, f"{k}: {mf[k]}"))
    return out


def web_xml_info(text: str, loc: str) -> tuple[dict, list[dict]]:
    servlets = re.findall(r"<servlet-class>\s*([^<]+?)\s*</servlet-class>", text)
    filters = re.findall(r"<filter-class>\s*([^<]+?)\s*</filter-class>", text)
    patterns = re.findall(r"<url-pattern>\s*([^<]+?)\s*</url-pattern>", text)
    info = {"servlets": servlets[:50], "filters": filters[:50], "url_patterns": patterns[:50]}
    out = []
    if servlets or filters:
        out.append(_finding("java_web_descriptor", "info",
                            f"web.xml maps {len(servlets)} servlet(s), {len(filters)} filter(s)", loc,
                            ", ".join((servlets + filters)[:8])))
    return info, out


def signing_info(extracted_dir: Path) -> tuple[dict, list[dict]]:
    meta = extracted_dir.rglob("META-INF/*") if extracted_dir.is_dir() else []
    sf = rsa = None
    for p in meta:
        if p.suffix.upper() == ".SF":
            sf = p
        elif p.suffix.upper() in (".RSA", ".DSA", ".EC"):
            rsa = p
    if not sf and not rsa:
        return {"signed": False}, []
    signer = ""
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        from cryptography import x509  # noqa: F401
        certs = pkcs7.load_der_pkcs7_certificates(rsa.read_bytes()) if rsa else []
        if certs:
            signer = certs[0].subject.rfc4514_string()
    except Exception:  # noqa: BLE001
        pass
    info = {"signed": True, "signer": signer}
    out = [_finding("java_signed", "info",
                    "jar is signed" + (f" by {signer}" if signer else " (signer unreadable)"),
                    "META-INF", signer)]
    return info, out


def _serialized_findings(paths: list[Path]) -> list[dict]:
    out: list[dict] = []
    for p in paths[:_MAX_CLASSES]:
        try:
            head = p.read_bytes()[:4]
        except OSError:
            continue
        if head == _SER_MAGIC:
            out.append(_finding("java_serialized_object", "high",
                                "serialized Java object stream (deserialization payload)",
                                f"file:{p.name}", p.name, "T1190"))
    return out


# --- top-level ---------------------------------------------------------------
def analyze(original: Path, extracted_dir: Path | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"module": "java", "status": "ok", "kind": "", "manifest": {},
                           "web_xml": {}, "signing": {}, "classes": 0, "jsp": 0,
                           "scripts": [], "findings": []}
    ext = original.suffix.lower()
    res["kind"] = ("war" if ext == ".war" else "ear" if ext == ".ear" else "jar"
                   if ext == ".jar" else "jsp" if ext in _JSP_EXT else "class")
    f = res["findings"]
    scripts: list[dict] = []

    # Files to consider: the extracted tree (jar/war) plus the original itself.
    files: list[Path] = []
    if extracted_dir and extracted_dir.is_dir():
        files = [p for p in sorted(extracted_dir.rglob("*")) if p.is_file()]
    if original.is_file():
        files.append(original)

    # MANIFEST + web.xml + signing (archive only).
    for p in files:
        name = p.name.upper()
        try:
            if name == "MANIFEST.MF":
                mf = parse_manifest(p.read_text("utf-8", "replace"))
                res["manifest"] = {k: mf[k] for k in list(mf)[:40]}
                f.extend(manifest_findings(mf, _rel(p, extracted_dir)))
            elif p.name.lower() == "web.xml":
                info, wf = web_xml_info(p.read_text("utf-8", "replace"), _rel(p, extracted_dir))
                res["web_xml"] = info
                f.extend(wf)
        except OSError:
            continue
    if extracted_dir and extracted_dir.is_dir():
        info, sf = signing_info(extracted_dir)
        res["signing"] = info
        f.extend(sf)
        f.extend(_serialized_findings(files))

    # .class and .jsp.
    n_class = n_jsp = 0
    budget = [_MAX_DECOMPILE]
    for p in files:
        e = p.suffix.lower()
        try:
            if e == ".class" and n_class < _MAX_CLASSES:
                blob = p.read_bytes()[:_MAX_FILE_BYTES]
                if blob[:4] != _CLASS_MAGIC:
                    continue
                n_class += 1
                fnd, sc = scan_class(p, blob, _rel(p, extracted_dir), budget)
                f.extend(fnd)
                if sc["hits"]:
                    scripts.append(sc)
            elif e in _JSP_EXT:
                n_jsp += 1
                fnd, sc = scan_jsp(p.read_text("utf-8", "replace")[:_MAX_FILE_BYTES], _rel(p, extracted_dir))
                f.extend(fnd)
                scripts.append(sc)
        except OSError:
            continue

    res["classes"] = n_class
    res["jsp"] = n_jsp
    res["scripts"] = scripts[:_MAX_ITEMS]
    res["counts"] = {"findings": len(f), "classes": n_class, "jsp": n_jsp, "scripts": len(res["scripts"])}
    if any(x["severity"] in ("high", "medium") for x in f):
        res["status"] = "ok_with_findings"
    return res


def analyze_one(path: Path, name: str) -> dict[str, Any]:
    """A single .class or .jsp child (for the nested path)."""
    item: dict[str, Any] = {"kind": "java", "file": name, "findings": []}
    e = Path(name).suffix.lower()
    try:
        if e == ".class":
            blob = path.read_bytes()[:_MAX_FILE_BYTES]
            fnd, sc = scan_class(path, blob, f"file:{name}")
        else:
            fnd, sc = scan_jsp(path.read_text("utf-8", "replace")[:_MAX_FILE_BYTES], f"file:{name}")
    except OSError as exc:
        item["error"] = str(exc)
        return item
    item["findings"] = fnd
    item["script"] = sc
    return item


def _rel(p: Path, extracted_dir: Path | None) -> str:
    if extracted_dir:
        try:
            return "file:" + p.relative_to(extracted_dir).as_posix()
        except ValueError:
            pass
    return f"file:{p.name}"
