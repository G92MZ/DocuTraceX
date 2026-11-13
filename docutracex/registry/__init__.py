"""Registry hives (regf) and .reg exports: ingested once into the case database
(``store``), checked for persistence / evasion / credential exposure (``rules``), and
explored afterwards from the Registry tab, the API and MCP without re-parsing.

Payloads kept in values (a PE, a script, an encoded PowerShell command in a binary /
string value: fileless malware) are carved and analysed as nested objects.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import re
from pathlib import Path
from typing import Any

from . import parse, rules, store

log = logging.getLogger(__name__)

MAX_FINDINGS_ROWS = 40          # rows quoted per rule in a finding / the summary
MAX_CARVED = 50
_B64 = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_SCRIPTY = re.compile(r"(?i)(powershell|pwsh|frombase64string|invoke-expression|\biex\b|-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}|"
                      r"mshta\s|wscript\.shell|createobject\(|\$env:|new-object\s+net\.webclient)")


def is_registry_file(path: Path) -> bool:
    return parse.is_hive(path) or parse.is_reg_text(path)


def _source_label(path: Path, case_root: Path) -> str:
    try:
        return str(path.relative_to(case_root))
    except ValueError:
        return path.name


def ingest(files: list[tuple[Path, str]], case_root: Path, work_dir: Path) -> dict[str, Any]:
    """Load every hive / .reg of ``files`` (path, label) into the case database."""
    dbp = store.db_path(case_root)
    con = store.create(dbp)
    sources: list[dict[str, Any]] = []
    try:
        for i, (path, label) in enumerate(files, start=1):
            rec: dict[str, Any] = {"id": i, "label": label, "file": _source_label(path, case_root), "logs": [],
                                   "error": ""}
            loader = store.Loader(con, i)
            try:
                if parse.is_hive(path):
                    info = parse.hive_info(path)
                    use, logs = parse.apply_logs(path, work_dir / f"{i}_{path.name}.recovered")
                    rec.update(kind="hive", hive_type=info["hive_type"], mount=info["mount"], logs=logs,
                               embedded_name=info["embedded_name"])
                    for what, row in parse.iter_hive(use, info["mount"]):
                        (loader.key if what == "key" else loader.value)(row)
                else:
                    keys, vals = parse.iter_reg(path)
                    rec.update(kind="reg", hive_type="", mount="")
                    for row in keys:
                        loader.key(row)
                    for row in vals:
                        loader.value(row)
            except Exception as exc:  # noqa: BLE001  (a broken hive: keep what was read)
                rec["error"] = f"{type(exc).__name__}: {exc}"[:300]
                log.warning("registry: %s: %s", path, exc)
            rec["keys"], rec["values"] = loader.finish()
            con.execute("INSERT INTO sources VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [i, label, rec["file"], rec.get("kind", ""), rec.get("hive_type", ""), rec.get("mount", ""),
                         rec["keys"], rec["values"], ",".join(rec["logs"]), rec["error"]])
            sources.append(rec)
    finally:
        store.finish_db(con)
    return {"db": str(dbp.relative_to(case_root)), "sources": sources}


def run_rules(dbp: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(hits per rule, findings)."""
    hits, findings = [], []
    reported: set[tuple] = set()          # (src, key, name) already in a finding
    for r in sorted(rules.RULES, key=lambda x: bool(x.get("dedupe"))):
        sql, args = rules.sql_for(r)
        rows = store.query(dbp, sql, args, 500)["rows"]
        if r.get("dedupe"):
            rows = [x for x in rows if (x[0], x[1], x[2]) not in reported]
        if not rows and not r.get("name") and not r.get("data"):
            ksql, kargs = rules.keys_sql_for(r)
            rows = store.query(dbp, ksql, kargs, 500)["rows"]
        if not rows:
            continue
        items = [{"src": x[0], "key": x[1], "name": x[2], "data": (x[3] or "")[:400], "last_write": x[4],
                  "source": x[6], "type": x[7]} for x in rows]
        sus = []
        if r.get("suspicious"):
            rx = re.compile(r["suspicious"])
            sus = [it for it in items if rx.search(it["data"] or "")]
        severity = r["severity"]
        shown = items
        if sus:
            severity, shown = r.get("suspicious_severity", "high"), sus
        hits.append({"rule": r["id"], "title": r["title"], "severity": severity, "attack": r["attack"],
                     "count": len(items), "suspicious": len(sus), "items": items[:MAX_FINDINGS_ROWS]})
        if severity == "info":
            continue
        reported.update((it["src"], it["key"], it["name"]) for it in shown)
        ev = "\n".join(f"{it['key']}" + (f" :: {it['name']} = {it['data'][:160]}" if it["name"] else "")
                       for it in shown[:8])
        findings.append({"tool": "registry", "rule": r["id"], "severity": severity,
                         "detail": f"{r['title']} — {len(shown)} entr{'y' if len(shown) == 1 else 'ies'}"
                                   + (" with a suspicious command" if sus else "") + " · " + ", ".join(r["attack"]),
                         "location": f"registry:{shown[0]['source']}", "evidence": ev})
    return hits, findings


def _root_cert_subjects(dbp: Path) -> list[dict[str, Any]]:
    """Subject / issuer of the certificates a .reg / hive adds to the trusted stores."""
    rows = store.query(dbp, """SELECT v.src, v."key", v.raw FROM vals v WHERE v.name = 'Blob' AND v.raw IS NOT NULL
        AND regexp_matches(v."key", '\\\\SystemCertificates\\\\(Root|AuthRoot|TrustedPublisher|CA)\\\\Certificates\\\\', 'i')
        LIMIT 50""")["rows"]
    out = []
    con = store.connect_ro(dbp)
    try:
        for src, key, _hex in rows:
            raw = con.execute('SELECT raw FROM vals WHERE src = ? AND "key" = ? AND name = \'Blob\'', [src, key]).fetchone()[0]
            der = _cert_from_blob(bytes(raw))
            info: dict[str, Any] = {"src": src, "key": key, "thumbprint": key.rsplit("\\", 1)[-1]}
            if der:
                info["sha1"] = hashlib.sha1(der).hexdigest()
                try:
                    from cryptography import x509
                    c = x509.load_der_x509_certificate(der)
                    info.update(subject=c.subject.rfc4514_string(), issuer=c.issuer.rfc4514_string(),
                                not_before=c.not_valid_before_utc.isoformat(), not_after=c.not_valid_after_utc.isoformat(),
                                self_signed=c.subject == c.issuer)
                except Exception:  # noqa: BLE001
                    pass
            out.append(info)
    finally:
        con.close()
    return out


def _cert_from_blob(blob: bytes) -> bytes | None:
    """The certificate (property 0x20) of a CERT_CONTEXT serialised property list."""
    i = 0
    while i + 12 <= len(blob):
        pid = int.from_bytes(blob[i:i + 4], "little")
        size = int.from_bytes(blob[i + 8:i + 12], "little")
        if pid == 0x20:
            return blob[i + 12:i + 12 + size]
        i += 12 + size
    return blob if blob[:1] == b"\x30" else None


def carve_payloads(dbp: Path, out_dir: Path) -> list[dict[str, Any]]:
    """Payloads stored in values: binaries (PE / archives / scripts in REG_BINARY), base64 blobs
    and script commands in string values. Written as files for the nested scan."""
    from . import store as st
    from ..decrypted import _magic_ext, sniff_ext
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    con = st.connect_ro(dbp)
    try:
        bins = con.execute("""SELECT src, "key", name, raw FROM vals WHERE raw IS NOT NULL AND size >= 64
            ORDER BY size DESC LIMIT 2000""").fetchall()
        texts = con.execute("""SELECT src, "key", name, data FROM vals WHERE type IN ('REG_SZ', 'REG_EXPAND_SZ', 'REG_MULTI_SZ')
            AND length(data) >= 40 AND (regexp_matches(data, '[A-Za-z0-9+/]{200,}') OR
            regexp_matches(data, '(?i)(powershell|pwsh|frombase64string|invoke-expression|mshta |wscript\\.shell|createobject\\(|-enc(odedcommand)? )'))
            LIMIT 2000""").fetchall()
    finally:
        con.close()

    def emit(src: int, key: str, name: str, data: bytes, ext: str, how: str) -> None:
        h = hashlib.sha256(data).hexdigest()
        if h in seen or len(out) >= MAX_CARVED:
            return
        seen.add(h)
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{key.rsplit(chr(92), 1)[-1]}_{name}")[:60]
        p = out_dir / f"reg{src}_{stem}_{h[:8]}{ext}"
        p.write_bytes(data)
        out.append({"src": src, "key": key, "name": name, "how": how, "size": len(data), "sha256": h,
                    "_path": str(p), "file": p.name})

    for src, key, name, raw in bins:
        raw = bytes(raw)
        ext = _magic_ext(raw)
        if ext:
            emit(src, key, name, raw, ext, "binary value")
            continue
        try:
            text = raw.decode("utf-16-le") if raw[1:2] == b"\0" else raw.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if text and _SCRIPTY.search(text):
            emit(src, key, name, text.encode("utf-8"), sniff_ext(text) or ".txt", "script in a binary value")
    for src, key, name, data in texts:
        for m in _B64.finditer(data or ""):
            try:
                dec = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4))
            except (binascii.Error, ValueError):
                continue
            ext = _magic_ext(dec)
            if ext:
                emit(src, key, name, dec, ext, "base64 in a string value")
        if _SCRIPTY.search(data or ""):
            emit(src, key, name, data.encode("utf-8"), sniff_ext(data) or ".cmd", "command in a string value")
    return out


def analyze(files: list[tuple[Path, str]], case_root: Path, work_dir: Path) -> dict[str, Any]:
    """Ingest + rules + certificates + payloads: the ``registry`` module result."""
    if not store.available():
        return {"module": "registry", "status": "error", "error": "DuckDB is not installed (pip install duckdb)",
                "findings": [], "counts": {"findings": 0}}
    res: dict[str, Any] = {"module": "registry", "status": "ok"}
    res.update(ingest(files, case_root, work_dir))
    dbp = store.db_path(case_root)
    hits, findings = run_rules(dbp)
    certs = _root_cert_subjects(dbp)
    for c in certs:
        if c.get("subject"):
            for f in findings:
                if f["rule"] == "reg_root_certificate":
                    f["evidence"] += f"\n{c['thumbprint']}: {c['subject']} (issuer {c.get('issuer', '')})"
    carved = carve_payloads(dbp, work_dir / "payloads")
    if carved:
        findings.append({"tool": "registry", "rule": "reg_payload_in_value", "severity": "high",
                         "detail": f"{len(carved)} payload(s) stored in registry values (PE, script, encoded command): "
                                   "fileless persistence · T1027.011, T1112",
                         "location": f"registry:{carved[0]['key']}",
                         "evidence": "\n".join(f"{c['key']} :: {c['name']} ({c['how']}, {c['size']} bytes)"
                                               for c in carved[:8])})
    for s in res["sources"]:
        if s.get("error"):
            findings.append({"tool": "registry", "rule": "reg_parse_error", "severity": "info",
                             "detail": f"{s['label']}: read with errors ({s['error']}); what could be read is loaded",
                             "location": f"registry:{s['label']}", "evidence": ""})
    res.update(hits=hits, certificates=certs, carved=[{k: v for k, v in c.items() if k != "_path"} for c in carved],
               _carved_paths=[(c["_path"], c["file"]) for c in carved], findings=findings,
               counts={"sources": len(res["sources"]), "keys": sum(s["keys"] for s in res["sources"]),
                       "values": sum(s["values"] for s in res["sources"]), "findings": len(findings),
                       "carved": len(carved)})
    return res
