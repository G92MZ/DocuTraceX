"""WinRAR SFX droppers whose archive sits after the SFX comment in the overlay."""

from __future__ import annotations

import pefile

import make_samples as ms

from docutracex.parsers import unpack


def test_rar_after_the_sfx_comment_is_detected() -> None:
    b = ms.sfx_rar_comment_exe()
    hits = unpack.heuristics(b, pefile.PE(data=b, fast_load=True))
    assert [h["family"] for h in hits] == ["sfxrar"]
    assert "inside the overlay" in hits[0]["evidence"]


def test_rar_bytes_without_a_winrar_stub_are_not_an_sfx() -> None:
    b = ms.sfx_rar_comment_exe().replace(b"WinRAR", b"Viewer")
    assert unpack.heuristics(b, pefile.PE(data=b, fast_load=True)) == []
