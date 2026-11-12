"""njRAT: builds with a custom splitter and no classic markers are still recognised."""

from __future__ import annotations

import make_samples as ms

from docutracex.c2 import dotnet_more


def test_custom_splitter_by_command_names() -> None:
    r = dotnet_more.extract_all(ms.njrat_custom_split_exe())[0]
    assert r["family"] == "njRAT" and r["summary"]["C2"] == ["cdn-update.example.net:5552"]
    assert r["summary"]["Splitter"] == "|S2026|" and "PLG" in r["summary"]["Commands"]


def test_classic_build_unchanged() -> None:
    r = dotnet_more.extract_all(ms.njrat_exe())[0]
    assert r["summary"]["Splitter"] == "|'|'|" and r["summary"]["Campaign"] == "Factura_2026"


def test_command_names_alone_are_not_enough() -> None:
    # a few short words and a host without a splitter: not njRAT
    assert dotnet_more.njrat(b"", ["ll", "inv", "ret", "Ex", "PLG", "cdn-update.example.net", "443"]) is None
