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
