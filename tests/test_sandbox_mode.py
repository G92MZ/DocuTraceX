"""Improve languages, T17: the emulators (V8, box-ps, ViperMonkey) obey one setting — always,
only where static evaluation stops, or off (static analysis only: no script code runs) — and what
they see is shown in the Resolution next to the static result.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _have_v8, _ms, client  # noqa: E402,F401

from docutracex import appsettings  # noqa: E402


@pytest.fixture()
def mode():  # noqa: ANN201
    old = appsettings.sandbox_mode()
    yield appsettings.set_sandbox_mode
    appsettings.set_sandbox_mode(old)


def test_setting_and_api(client, mode) -> None:  # noqa: ANN001,F811
    r = client.put("/api/settings/analysis", json={"sandbox": "fallback"}).json()
    assert r["sandbox"] == "fallback" and r["sandbox_modes"] == ["always", "fallback", "off"]
    assert client.get("/api/settings/analysis").json()["sandbox"] == "fallback"
    assert client.put("/api/settings/analysis", json={"sandbox": "sometimes"}).status_code == 400
    mode("off")
    assert not appsettings.sandbox_wanted({"stages": []})
    mode("fallback")
    assert appsettings.sandbox_wanted({"stages": []}, obfuscated=True)
    assert not appsettings.sandbox_wanted({"stages": [{"kind": "exec"}]}, obfuscated=True)
    assert not appsettings.sandbox_wanted(None, obfuscated=False)
    mode("always")
    assert appsettings.sandbox_wanted({"stages": [{"kind": "exec"}]})


@pytest.mark.skipif(not _have_v8(), reason="STPyV8 not installed")
def test_off_runs_no_code_and_always_shows_what_the_sandbox_saw(client, mode) -> None:  # noqa: ANN001,F811
    mode("off")
    _cid, res = _analyze(client, "sample_chain_dropper.js", _ms().chain_dropper_js())
    js = json.loads((res / "javascript.json").read_text())["scripts"][0]
    assert not js["sandbox"].get("log") and js["sandbox"]["skipped"] == "emulation off"
    assert js["resolution"]["stages"]                         # the static result stands on its own
    mode("always")
    _cid, res = _analyze(client, "sample_chain_dropper.js", _ms().chain_dropper_js())
    js = json.loads((res / "javascript.json").read_text())["scripts"][0]
    seen = js["resolution"]["sandbox"]
    assert seen["tool"].startswith("V8") and any(e["kind"] == "writes" for e in seen["events"])


@pytest.mark.skipif(not _have_v8(), reason="STPyV8 not installed")
def test_fallback_skips_what_static_resolved(client, mode) -> None:  # noqa: ANN001,F811
    mode("fallback")
    _cid, res = _analyze(client, "sample_js_loader.js", _ms().js_loader())
    js = json.loads((res / "javascript.json").read_text())["scripts"][0]
    assert js["resolution"]["stages"] and not js["sandbox"].get("log")
