"""Results holding lone surrogates (bytes of a sample that did not decode,
kept as \\udcXX) are still written — as valid UTF-8 JSON that reads back the same."""

from __future__ import annotations

from pathlib import Path

from docutracex.storage import read_json, write_json


def test_lone_surrogates_round_trip(tmp_path: Path) -> None:
    bad = b"Factura \xe1\xff\xfe.pdf".decode("utf-8", "surrogateescape")
    data = {"name": bad, "text": "año €", "map": {"k\udc80": [bad, 1]}}
    p = tmp_path / "results" / "x.json"
    write_json(p, data)
    p.read_bytes().decode("utf-8")              # valid UTF-8
    assert read_json(p) == data
    assert not list(p.parent.glob("*.tmp"))


def test_plain_text_stays_readable(tmp_path: Path) -> None:
    p = tmp_path / "y.json"
    write_json(p, {"t": "contraseña €"})
    assert "contraseña €" in p.read_text(encoding="utf-8")
