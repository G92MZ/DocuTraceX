"""Every child shows in Nested: deep analysis up to the limits, the rest listed;
a later batch (decrypted stages) never replaces an earlier one (installer files)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from docutracex import nested  # noqa: E402
from docutracex.storage import CasePaths  # noqa: E402


def _files(cp: CasePaths, n: int) -> list[dict]:
    d = cp.extracted_dir / "unpacked" / "kit"
    d.mkdir(parents=True, exist_ok=True)
    out = []
    for i in range(n):
        f = d / f"f{i:03d}.txt"
        f.write_text(f"component {i}\n")
        out.append({"path": str(f), "filename": f.name, "origin": "MSI (7-Zip extraction)", "source": "unpacked"})
    return out


def test_children_over_the_limit_are_listed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(nested, "MAX_CHILDREN", 5)
    cp = CasePaths("c1", cases_dir=tmp_path / "cases")
    res = nested.scan_children(_files(cp, 12), cp)
    assert len(res["tree"]) == 12 and res["listed_children"] == 7
    listed = [n for n in res["tree"] if n.get("listed_only")]
    assert len(listed) == 7 and all(n.get("sha256") and n.get("stored_path") for n in listed)
    assert all(n["source"] == "unpacked" for n in res["tree"])


def test_archive_members_over_the_limit_are_listed(tmp_path: Path, monkeypatch) -> None:
    import make_samples as ms
    monkeypatch.setattr(nested, "MAX_CHILDREN", 10)
    cp = CasePaths("c2", cases_dir=tmp_path / "cases")
    (cp.extracted_dir / "x").mkdir(parents=True, exist_ok=True)
    z = cp.extracted_dir / "x" / "kit.zip"
    z.write_bytes(ms.many_files_zip(30))
    res = nested.scan_children([{"path": str(z), "filename": "kit.zip"}], cp)
    node = res["tree"][0]
    assert len(node["children"]) == 30 and node["listed_children"] == 20


def test_later_batch_does_not_replace_installer_files(tmp_path: Path) -> None:
    cp = CasePaths("c3", cases_dir=tmp_path / "cases")
    first = nested.scan_children(_files(cp, 3), cp)
    d = cp.extracted_dir / "stages"
    d.mkdir(parents=True, exist_ok=True)
    (d / "stage.bin").write_bytes(b"\x00stage\x00" * 20)
    second = nested.scan_children([{"path": str(d / "stage.bin"), "filename": "stage.bin",
                                    "origin": "python: escaped bytes", "source": "decrypted"}], cp)
    merged = nested.merge(first, second)
    names = [n["filename"] for n in merged["tree"]]
    assert names == ["f000.txt", "f001.txt", "f002.txt", "stage.bin"]
    # a re-run of the same kind replaces its own batch only
    again = nested.merge(merged, second)
    assert [n["filename"] for n in again["tree"]] == names
