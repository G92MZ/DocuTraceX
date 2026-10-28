"""Hex tab: byte windows, search, entropy, regions and path safety."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

from docutracex import hexview  # noqa: E402


def test_search_modes_and_entropy(tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    data = b"MZ\x90\x00" + b"\x00" * 2000 + "http://x.example".encode() + "Factura".encode("utf-16-le") + bytes(range(256)) * 8
    f.write_bytes(data)
    assert hexview.search(f, "hex", "4D 5A ?? 00")["hits"] == [[0, 4]]
    assert hexview.search(f, "hex", "4d5a90")["hits"] == [[0, 3]]
    assert hexview.search(f, "ascii", "HTTP", ignore_case=True)["hits"][0][0] == 2004
    assert hexview.search(f, "utf16", "Factura")["hits"][0][0] == data.index("Factura".encode("utf-16-le"))
    assert hexview.search(f, "regex", r"https?://[a-z.]+")["hits"][0][0] == 2004
    with pytest.raises(ValueError):
        hexview.search(f, "hex", "zz")
    e = hexview.entropy(f)
    assert e["size"] == len(data) and max(e["values"]) > 7.5 and min(e["values"]) < 1
    r = hexview.read(f, 2, 4)
    import base64
    assert base64.b64decode(r["data"]) == b"\x90\x00\x00\x00" and r["size"] == len(data)


def test_regex_cannot_hang(tmp_path: Path, monkeypatch) -> None:
    f = tmp_path / "b.bin"
    f.write_bytes(b"a" * 40 + b"!")
    monkeypatch.setattr(hexview, "REGEX_TIMEOUT", 2)
    r = hexview.search(f, "regex", r"(a+)+$")
    assert r["hits"] == [] and "longer" in r.get("error", "")


def test_api_lists_reads_and_refuses_escapes(client) -> None:
    import base64
    cid, _ = _analyze(client, "invoice_helper.dll", _ms().lief_helper_dll())
    files = client.get(f"/api/cases/{cid}/hex/files").json()["files"]
    orig = files[0]
    assert orig["group"] == "original" and orig["path"].startswith("original/")
    r = client.get(f"/api/cases/{cid}/hex/read", params={"path": orig["path"], "offset": 0, "length": 2}).json()
    assert base64.b64decode(r["data"]) == b"MZ"
    hits = client.get(f"/api/cases/{cid}/hex/search", params={"path": orig["path"], "q": "RSDS", "mode": "ascii"}).json()
    assert hits["hits"]
    regions = client.get(f"/api/cases/{cid}/hex/regions", params={"path": orig["path"]}).json()["regions"]
    if regions:                                   # LIEF installed: sections + overlay
        assert any(x["name"] == "overlay" for x in regions)
    bad = client.get(f"/api/cases/{cid}/hex/read", params={"path": "../../etc/passwd"})
    assert bad.status_code == 400


def test_decode_recipes(tmp_path: Path) -> None:
    import base64
    import gzip

    secret = b"MZ" + b"server=http://billing-portal.example/inv/c2\r\n" * 4
    xored = bytes(c ^ 0x41 for c in gzip.compress(secret))
    blob = b"pre '" + base64.b64encode(xored) + b"' post"
    f = tmp_path / "s.ps1"
    f.write_bytes(blob)
    off, n = 5, len(base64.b64encode(xored))
    out, done = hexview.apply_recipe(f.read_bytes()[off:off + n], hexview.parse_recipe("base64 | xor 41 | zlib"))
    assert out == secret and done == ["base64", "xor 0x41", "inflate (gzip)"]
    # single-byte key found automatically (gzip magic)
    out, done = hexview.apply_recipe(xored, [("xor", "auto")])
    assert out[:2] == b"\x1f\x8b" and done == ["xor 0x41 (auto)"]
    assert hexview.apply_recipe(b"4d 5a 90", [("hex", "")])[0] == b"MZ\x90"
    assert hexview.apply_recipe(b"abc", [("reverse", "")])[0] == b"cba"
    p = hexview.decode_preview(f, off, n, "base64|xor 0x41|zlib")
    assert p["size"] == len(secret) and p["type"] == "PE / MZ"
    with pytest.raises(ValueError):
        hexview.parse_recipe("rot13")
    with pytest.raises(ValueError):
        hexview.apply_recipe(b"not compressed", [("zlib", "")])


def test_structures_pe_and_elf(tmp_path: Path) -> None:
    ms = _ms().ml_samples()
    dll = tmp_path / "calc.dll"
    dll.write_bytes(ms["ml/sample_win32_invoice_calc.dll"])
    names = {r["name"]: r for r in hexview.structures(dll)}
    assert {"DOS header", "Rich header", "COFF header", "section table", "section .text", "resources",
            "debug directory"} <= set(names)
    assert names["Rich header"]["kind"] == "rich" and names["section .text"]["kind"] == "code"
    net = tmp_path / "loader.exe"
    net.write_bytes(ms["ml/sample_dotnet_loader.exe"])
    assert ".NET metadata (BSJB)" in {r["name"] for r in hexview.structures(net)}
    elf = tmp_path / "miner"
    elf.write_bytes(ms["ml/sample_elf_miner"])
    assert {"ELF header", "section .text", "section .rodata"} <= {r["name"] for r in hexview.structures(elf)}
    assert hexview.structures(tmp_path / "loader.exe") and not hexview.structures(Path(__file__))


def test_extract_selection_becomes_nested_child(client) -> None:
    import base64
    import gzip
    import json
    import time

    from docutracex.config import settings

    cfg = b"[sync]\r\nserver=http://billing-portal.example/inv/c2\r\n"
    b64 = base64.b64encode(gzip.compress(cfg))
    src = b"$c = Get-Cfg '" + b64 + b"'\r\nWrite-Host $c\r\n"
    cid, res = _analyze(client, "cfg_loader.ps1", src)
    r = client.post(f"/api/cases/{cid}/hex/extract", json={"path": "original/cfg_loader.ps1", "offset": 14,
                                                            "length": len(b64), "recipe": "base64 | zlib",
                                                            "name": "cfg.ini"})
    assert r.status_code == 200, r.text
    tid = r.json()["task"]["id"]
    for _ in range(1200):
        t = next((x for x in client.get("/api/tasks").json()["tasks"] if x["id"] == tid), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.05)
    tree = json.loads((res / "nested.json").read_text())["tree"]
    node = next(n for n in tree if n.get("source") == "hex")
    assert node["filename"] == "01_cfg.ini" and node["recipe"][1:] == ["base64", "inflate (gzip)"]
    assert (settings.cases_dir / cid / "extracted" / "hex" / "01_cfg.ini").read_bytes() == cfg
    assert client.get(f"/api/cases/{cid}/hex/extracts").json()["extracts"][0]["name"] == "cfg.ini"
    assert any(f["path"].endswith("01_cfg.ini") for f in client.get(f"/api/cases/{cid}/hex/files").json()["files"])
    # a bad recipe is refused before anything is recorded
    bad = client.post(f"/api/cases/{cid}/hex/extract", json={"path": "original/cfg_loader.ps1", "offset": 0,
                                                              "length": 10, "recipe": "zlib"})
    assert bad.status_code == 400 and len(client.get(f"/api/cases/{cid}/hex/extracts").json()["extracts"]) == 1
    # removing it re-analyses without the child
    tid = client.delete(f"/api/cases/{cid}/hex/extract/0").json()["task"]["id"]
    for _ in range(1200):
        t = next((x for x in client.get("/api/tasks").json()["tasks"] if x["id"] == tid), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.05)
    tree = (json.loads((res / "nested.json").read_text()) or {}).get("tree") or []
    assert not [n for n in tree if n.get("source") == "hex"]
    assert not (settings.cases_dir / cid / "extracted" / "hex").exists()
