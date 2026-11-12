"""Go with its pclntab hidden (garble / modified toolchain): the runtime's own messages still say Go."""

from __future__ import annotations

import make_samples as ms

from docutracex.golang import detect


def test_runtime_messages_without_pclntab() -> None:
    r = detect.identify(ms.go_hidden_pclntab_elf())
    assert r["state"] == "Likely" and "runtime_messages" in {e["kind"] for e in r["evidence"]}
    assert r["traits"]["pclntab_missing"] and "garble" in r["traits"]["garble"]["reason"]


def test_few_messages_are_not_go() -> None:
    blob = b"\x7fELF" + b"\x00" * 60 + b"GODEBUG\x00index out of range\x00"
    assert detect.identify(blob)["state"] in ("Not detected", "Inconclusive")


def test_normal_go_unchanged() -> None:
    for k, v in ms.go_samples().items():
        if k != "go/sample_go_hidden_pclntab":
            r = detect.identify(v)
            assert r["state"] == "Confirmed" and "runtime_messages" not in {e["kind"] for e in r["evidence"]}, k
