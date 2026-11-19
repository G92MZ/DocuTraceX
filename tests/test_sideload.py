"""DLL side-loading: a signed program next to a DLL with a system library's name."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from docutracex import sideload

ms = pytest.importorskip("make_samples")
bk = pytest.importorskip("binkit")


def _entries(tmp: Path, files: dict[str, bytes], folder: str = "Factura") -> list[tuple[str, str]]:
    out = []
    for n, b in files.items():
        p = tmp / n
        p.write_bytes(b)
        out.append((f"{folder}/{n}", str(p)))
    return out


def test_signed_exe_and_unsigned_proxy_dll(tmp_path: Path) -> None:
    got = sideload.findings(_entries(tmp_path, ms.sideloading_parts()), "x.zip")
    assert len(got) == 1
    f = got[0]
    assert f["rule"] == "dll_sideloading" and f["severity"] == "high" and f["attack"] == "T1574.002"
    assert "which imports it" in f["detail"] and "Visor Facturas Example S.L." in f["detail"]
    assert "17 of its 18 exports are forwarded" in f["detail"] and "Iniciar" in f["detail"]
    r = sideload.pairs(_entries(tmp_path, ms.sideloading_parts()))[0]
    assert r["exe_signed"] and not r["dll_signed"] and r["imported"]


def test_other_signer_and_genuine_microsoft_copy(tmp_path: Path) -> None:
    exe = ms._fake_signed_by(bk.pe(bits=64, imports={"dbghelp.dll": ["MiniDumpWriteDump"]}), "Visor Facturas Example S.L.")
    other = ms._fake_signed_by(bk.pe(bits=64, dll=True, exports=["MiniDumpWriteDump"]), "Otra Empresa Example Ltd")
    f = sideload.findings(_entries(tmp_path, {"app.exe": exe, "dbghelp.dll": other}), "x")[0]
    assert f["severity"] == "high" and "signed by someone else" in f["detail"]
    ms_copy = ms._fake_signed_by(bk.pe(bits=64, dll=True, exports=["MiniDumpWriteDump"]), "Microsoft Corporation")
    f = sideload.findings(_entries(tmp_path, {"app.exe": exe, "dbghelp.dll": ms_copy}), "x")[0]
    assert f["severity"] == "low" and "redistributable" in f["detail"]


def test_nothing_without_the_pattern(tmp_path: Path) -> None:
    exe = ms._fake_signed_by(bk.pe(bits=64, imports={"helper.dll": ["Run"]}), "Visor Facturas Example S.L.")
    helper = bk.pe(bits=64, dll=True, exports=["Run"])
    assert sideload.findings(_entries(tmp_path, {"app.exe": exe, "helper.dll": helper}), "x") == []   # not a system name
    parts = ms.sideloading_parts()
    ents = _entries(tmp_path, {"VisorFacturas.exe": parts["VisorFacturas.exe"]}, "a") + \
        [("b/version.dll", str(tmp_path / "version.dll"))]
    (tmp_path / "version.dll").write_bytes(parts["version.dll"])
    assert sideload.findings(ents, "x") == []                                               # different folders
    # a text file called version.dll is not a DLL
    (tmp_path / "v.dll").write_bytes(b"not a pe")
    assert sideload.findings(_entries(tmp_path, {"app.exe": exe}) + [("Factura/version.dll", str(tmp_path / "v.dll"))],
                             "x") == []


@pytest.mark.parametrize("name,rule", [("sample_dll_sideloading.zip", "dll_sideloading"),
                                       ("sample_dll_sideloading.iso", "dll_sideloading"),
                                       ("sample_dll_sideloading.msi", "msi_dll_sideloading")])
def test_samples_end_to_end(tmp_path: Path, name: str, rule: str) -> None:
    from docutracex import analyze, cases, findings
    data = ms.sideloading_samples()[name]
    m = cases.create_case(io.BytesIO(data), name, cases_dir=tmp_path)
    root = tmp_path / m["analysis_id"]
    analyze.analyze_case(root)
    mods = {p.stem: json.loads(p.read_text()) for p in (root / "results").glob("*.json")}
    got = [f for f in findings.consolidate(mods) if f["rule"] == rule]
    assert got and got[0]["severity"] == "high"


def test_nested_zip_in_zip(tmp_path: Path) -> None:
    """The pair one level down (a ZIP inside a ZIP) is found by the nested analysis."""
    import zipfile

    from docutracex import analyze, cases, findings
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("factura.zip", ms.sideloading_samples()["sample_dll_sideloading.zip"])
    m = cases.create_case(io.BytesIO(buf.getvalue()), "outer.zip", cases_dir=tmp_path)
    root = tmp_path / m["analysis_id"]
    analyze.analyze_case(root)
    mods = {p.stem: json.loads(p.read_text()) for p in (root / "results").glob("*.json")}
    assert any(f["rule"] == "dll_sideloading" for f in findings.consolidate(mods))


# --- HijackLibs catalogue (downloaded at run time; here an invented stand-in with its shape) ---

def _catalogue() -> list[dict]:
    """Invented entries in the shape of hijacklibs.net/api/hijacklibs.json (no real data)."""
    fill = [{"Name": f"relleno{i}.dll", "Vendor": "Example", "ExpectedLocations": ["%PROGRAMFILES%\\Example"],
             "VulnerableExecutables": [{"Path": f"%PROGRAMFILES%\\Example\\app{i}.exe", "Type": "Sideloading"}],
             "url": f"https://hijacklibs.net/entries/3rd_party/example/relleno{i}.html"} for i in range(220)]
    return fill + [
        {"Name": "libcurl.dll", "Vendor": "curl", "ExpectedLocations": ["%PROGRAMFILES%\\Example\\updater"],
         "VulnerableExecutables": [{"Path": "%PROGRAMFILES%\\Example\\updater\\GUP.exe", "Type": "Sideloading"}],
         "url": "https://hijacklibs.net/entries/3rd_party/curl/libcurl.html"},
        {"Name": "facturahelper.dll", "Vendor": "Microsoft", "ExpectedLocations": ["%SYSTEM32%"],
         "VulnerableExecutables": [{"Path": "%SYSTEM32%\\visor.exe", "Type": "Sideloading",
                                    "Condition": "loads it at start"}], "url": ""},
        {"Name": "vcruntime140.dll", "Vendor": "Microsoft", "ExpectedLocations": ["%SYSTEM32%"],
         "VulnerableExecutables": [{"Path": "%PROGRAMFILES%\\Example\\tool.exe", "Type": "Sideloading"}], "url": ""},
        {"Name": "version.dll", "Vendor": "Microsoft", "ExpectedLocations": ["%SYSTEM32%", "%SYSWOW64%"],
         "VulnerableExecutables": [{"Path": "%PROGRAMFILES%\\Example\\VisorFacturas.exe", "Type": "Sideloading"}],
         "url": "https://hijacklibs.net/entries/microsoft/built-in/version.html"},
    ]


@pytest.fixture()
def hl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from docutracex import hijacklibs
    from docutracex.config import settings
    monkeypatch.setattr(settings, "tools_dir", tmp_path / "tools")
    hijacklibs._cache.update(mtime=None, dlls=None, count=0)
    p = hijacklibs.path()
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps(_catalogue()))
    yield hijacklibs
    hijacklibs._cache.update(mtime=None, dlls=None, count=0)


def test_catalogue_status_and_names(hl) -> None:
    st = hl.status()
    assert st["source"] == "hijacklibs" and st["dlls"] == 224 and st["system"] == 3
    cat = sideload.catalogue()
    assert cat["facturahelper.dll"]["system"] and cat["libcurl.dll"]["hosts"].keys() == {"gup.exe"}
    assert cat["winhttp.dll"]["source"] == "builtin"              # the built-in names stay


def test_vendor_dll_with_its_known_host(tmp_path: Path, hl) -> None:
    data = ms.sideloading_samples()["sample_dll_sideloading_vendor.zip"]
    import zipfile
    files = {}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for n in z.namelist():
            files[n.split("/")[-1]] = z.read(n)
    f = sideload.findings(_entries(tmp_path, files, "Actualizador_Facturas"), "x")
    assert len(f) == 1 and f[0]["severity"] == "high"
    assert "HijackLibs lists gup.exe" in f[0]["detail"] and "expected in %PROGRAMFILES%" in f[0]["detail"]
    assert "hijacklibs.net/entries/3rd_party/curl/libcurl.html" in f[0]["evidence"]


def test_pairs_that_hold_together_are_quiet(tmp_path: Path, hl) -> None:
    """A vendor DLL next to its listed program, both unsigned or both by the same signer, and an
    app-local runtime (vcruntime140.dll) next to a program: how software ships. Nothing."""
    exe = bk.pe(bits=64, imports={"libcurl.dll": ["curl_easy_init"], "vcruntime140.dll": ["memset"]})
    curl = bk.pe(bits=64, dll=True, exports=["curl_easy_init"])
    vcr = bk.pe(bits=64, dll=True, exports=["memset"])
    assert sideload.findings(_entries(tmp_path, {"GUP.exe": exe, "libcurl.dll": curl, "vcruntime140.dll": vcr}),
                             "x") == []
    s_exe = ms._fake_signed_by(exe, "Updater Example Ltd")
    s_curl = ms._fake_signed_by(curl, "Updater Example Ltd")
    assert sideload.findings(_entries(tmp_path, {"GUP.exe": s_exe, "libcurl.dll": s_curl}), "x") == []
    f = sideload.findings(_entries(tmp_path, {"GUP.exe": s_exe, "vcruntime140.dll": vcr}), "x")
    assert f and f[0]["severity"] == "high"          # a signed program and an unsigned runtime: does not hold


def test_vendor_dll_without_the_catalogue_is_quiet(tmp_path: Path) -> None:
    data = ms.sideloading_samples()["sample_dll_sideloading_vendor.zip"]
    import zipfile
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        files = {n.split("/")[-1]: z.read(n) for n in z.namelist()}
    assert sideload.findings(_entries(tmp_path, files), "x") == []


def test_catalogue_names_and_known_host_on_a_system_dll(tmp_path: Path, hl) -> None:
    """A Windows name only the catalogue knows; and the version.dll pair where the program is a
    listed host: the finding names it."""
    exe = bk.pe(bits=64, imports={"facturahelper.dll": ["Run"]})
    dll = bk.pe(bits=64, dll=True, exports=["Run"])
    f = sideload.findings(_entries(tmp_path, {"visor.exe": exe, "facturahelper.dll": dll}), "x")
    assert f and f[0]["severity"] == "medium" and "loads it at start" in f[0]["detail"]    # nothing odd but the name
    f = sideload.findings(_entries(tmp_path, ms.sideloading_parts()), "x")[0]
    assert "HijackLibs lists visorfacturas.exe" in f["detail"]


def test_download_from_json_and_repo_zip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hl) -> None:
    """hijacklibs.net JSON first; if it fails, the repository's YAML files (needs PyYAML)."""
    import zipfile

    from docutracex import mailintel
    body_json = json.dumps(_catalogue()).encode()
    yaml = pytest.importorskip("yaml")
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        for e in _catalogue():
            z.writestr(f"HijackLibs-main/yml/3rd_party/x/{e['Name'][:-4]}.yml", yaml.safe_dump(e))
    calls: list[str] = []

    class Op:
        def __init__(self, fail_json: bool) -> None:
            self.fail_json = fail_json

        def open(self, req, timeout=60):
            url = req.full_url
            calls.append(url)
            if "hijacklibs.net" in url and self.fail_json:
                raise OSError("blocked")
            data = body_json if "hijacklibs.net" in url else zbuf.getvalue()

            class R(io.BytesIO):
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False
            return R(data)
    for fail in (False, True):
        calls.clear()
        monkeypatch.setattr(mailintel, "_routes", lambda proxy, f=fail: [("direct", Op(f))])
        st = hl.download()
        assert st["source"] == "hijacklibs" and st["dlls"] == 224
        assert any("codeload.github.com" in c for c in calls) == fail
