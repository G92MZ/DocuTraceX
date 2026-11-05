"""IOC noise from the tools themselves (their project URLs in banners) and PDF
dictionary syntax read as Windows commands (/Type /Annot)."""

from __future__ import annotations

from docutracex import ioc


def _vals(sources: list[dict]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for i in ioc.extract(sources)["iocs"]:
        out.setdefault(i["type"], []).append(i["value"])
    return out


def test_pdf_names_are_not_type_commands() -> None:
    v = _vals([{"module": "pdf", "location": "objects[1]/snippet",
                "text": "<< /Type /Annot /Subtype /Link >>\n<< /Type /XObject /Width 1707 /Length 512216 >>\n"
                        "Type /FontDescriptor /XHeight 547\nType /ExtGState /ca 1\n"},
               {"module": "vba", "location": "vba/code", "text": 'Shell "cmd /c type C:\\Users\\a\\x.txt"\n'}])
    assert v.get("command") == ['cmd /c type C:\\Users\\a\\x.txt']


def test_tool_project_urls_in_tool_output_are_not_iocs() -> None:
    v = _vals([{"module": "pdftools", "location": "pdftools/x.pdf › tools/peepdf/output",
                "text": "peepdf https://github.com/digitalsleuth/peepdf-3 (github.com/digitalsleuth/peepdf-3)\n"
                        "docs https://pypdf.readthedocs.io/en/latest/ bugs https://github.com/py-pdf/pypdf/issues\n"
                        "/URI (https://evil.example/invoice)\n"}])
    assert v.get("url") == ["https://evil.example/invoice"] and v.get("domain") == ["evil.example"]


def test_unrelated_repos_stay_iocs() -> None:
    v = _vals([{"module": "vba", "location": "vba/code",
                "text": 'u = "https://github.com/someone/payload/raw/main/a.exe"\nh = "github.com/someone/thing"\n'}])
    assert "https://github.com/someone/payload/raw/main/a.exe" in v.get("url", [])
    assert "github.com" in v.get("domain", [])


def test_installed_package_urls_are_tool_urls_only_in_tool_output(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(ioc, "_INSTALLED", ({"github.com/acme/pdftool"},
                                            {("pdftool.example", ()), ("discord.gg", ("acme",))}))
    assert ioc._is_installed_tool_url("https://github.com/acme/pdftool/issues")
    assert ioc._is_installed_tool_url("https://docs.pdftool.example/x") is False      # exact host only
    assert ioc._is_installed_tool_url("https://pdftool.example/manual")
    assert ioc._is_installed_tool_url("https://discord.gg/acme")
    assert not ioc._is_installed_tool_url("https://discord.gg/stealer-drop")          # a prefix, not the service
    banner = "pdftool 1.0 https://github.com/acme/pdftool https://pdftool.example/\n/URI (https://discord.gg/stealer-drop)\n"
    v = _vals([{"module": "pdftools", "location": "pdftools/x.pdf › tools/pdftool/output", "text": banner}])
    assert v.get("url") == ["https://discord.gg/stealer-drop"]
    v = _vals([{"module": "vba", "location": "vba/code", "text": 'x = "https://pdftool.example/"\n'}])
    assert v.get("url")       # outside tool output it is still reported
