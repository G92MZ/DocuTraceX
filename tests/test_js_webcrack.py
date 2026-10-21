"""Tests for the webcrack JS-deobfuscation wrapper (graceful without Node)."""

from __future__ import annotations

from docutracex.parsers import js_webcrack


def test_unavailable_without_provisioning(monkeypatch) -> None:
    # No portable Node and no webcrack install -> unavailable, and deobfuscate
    # returns the input unchanged instead of raising.
    monkeypatch.setattr(js_webcrack.settings, "node_executable", lambda: None)
    monkeypatch.setattr(js_webcrack, "_node", lambda: None)
    assert js_webcrack.available() is False
    st = js_webcrack.status()
    assert st["available"] is False and "Node" in st["detail"]
    out = js_webcrack.deobfuscate("var a = 1;")
    assert out["changed"] is False and out["code"] == "var a = 1;"
    assert out["error"] and "provision" in out["error"]


def test_empty_code_is_safe(monkeypatch) -> None:
    monkeypatch.setattr(js_webcrack, "_node", lambda: None)
    assert js_webcrack.deobfuscate("")["changed"] is False
