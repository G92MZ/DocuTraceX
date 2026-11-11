"""Go phase 6: scripts / templates held as string literals, notable third-party
modules and the standard-library packages that say what a binary can do."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

import make_samples as ms
from docutracex import codeanalysis as ca
from docutracex.codeanalysis import resources
from docutracex.golang import binfmt

needs_rizin = pytest.mark.skipif(not ca.available(), reason="Rizin + rz-ghidra not provisioned")


def test_script_and_template_literals() -> None:
    data = ms.go_code_exe()
    got = {x["language"]: x for x in resources.script_literals(data, binfmt.parse(data))}
    assert set(got) == {"PowerShell", "Go template"}
    ps = got["PowerShell"]
    assert ps["ext"] == ".ps1" and ps["markers"] >= 3 and b"DownloadFile" in ps["data"]
    assert data[ps["offset"]:ps["offset"] + 10] == ps["data"][:10]                    # file offset (Hex tab)
    assert b"{{range .Lines}}" in got["Go template"]["data"]


def test_prose_and_runtime_text_are_not_scripts() -> None:
    import binkit as bk
    prose = (b"runtime: program exceeds 10000-thread limit; fatal error: all goroutines are asleep - deadlock! "
             b"This function returns the set of values for the given key, if any; see the documentation for details. ")
    data = bk.pe(bits=64, sections=[(".rdata", b"\x00" + prose * 3 + b"\x00", 0x40000040)])
    assert resources.script_literals(data, binfmt.parse(data)) == []


def test_standard_library_and_notable_modules() -> None:
    names = ["main.main", "os/exec.Command", "os/exec.(*Cmd).Output", "net/smtp.SendMail",
             "html/template.(*Template).Execute", "fmt.Println", "github.com/bwmarrin/discordgo.New"]
    deps = resources.go_dependencies({"path": "example.com/agent", "deps": [
        {"path": "github.com/bwmarrin/discordgo"}, {"path": "golang.org/x/sys"}]}, names)
    std = {x["package"]: x for x in deps["std_notable"]}
    assert std["os/exec"]["functions"] == 2 and "exfiltration" in std["net/smtp"]["why"]
    assert "html/template" in std and "fmt" not in std
    assert {"module": "github.com/bwmarrin/discordgo", "why": "Discord bot (C2 / exfiltration?)"} in deps["notable"]


@needs_rizin
def test_case_carves_script_literals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze, cases
    from docutracex.codeanalysis import case as code_case
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    monkeypatch.setattr(settings, "goresym_executable", lambda: None)
    m = cases.create_case(io.BytesIO(ms.go_code_exe()), "factura.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    root = tmp_path / m["analysis_id"]
    go = read_json(CasePaths(m["analysis_id"]).subresult("golang"))
    obj = go["objects"][0]
    assert obj["code"]["resources"]["scripts"] == 2 and obj["code"]["resources"]["std_notable"] >= 4
    full = code_case.load(root, obj["sha256"], "go")
    ps = next(x for x in full["resources"]["scripts"] if x["language"] == "PowerShell")
    assert ps["stored_path"].endswith(".ps1") and (root / ps["stored_path"]).is_file()
    f = next(x for x in go["findings"] if x["rule"] == "code:embedded_script")
    assert f["severity"] == "medium" and "PowerShell" in f["detail"] and "template" not in f["detail"].lower()
    nested = read_json(CasePaths(m["analysis_id"]).subresult("nested")) or {}
    assert "script_" in str(nested)                                  # carved and analysed as a nested child
