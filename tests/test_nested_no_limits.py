"""Nested analyses every child in depth: no cap on how many, and no shallow depth cap.

- an installer kit with 80 files: all 80 analysed (none "listed only");
- the invoice lure buried 15 archives deep (samples: nested/sample_deep_nesting.zip): every
  level opened and the JScript at the bottom deobfuscated;
- a file equal to one it is inside (a file that contains itself) is not opened again.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))

from docutracex import nested  # noqa: E402
from docutracex.storage import CasePaths  # noqa: E402


def _ms():  # noqa: ANN202
    from test_js_techniques import _ms as load
    return load()


def _walk(nodes, depth=1):  # noqa: ANN001, ANN202
    for n in nodes:
        yield n, depth
        yield from _walk(n.get("children") or [], depth + 1)


def _case(tmp_path: Path, name: str, data: bytes) -> tuple[CasePaths, Path]:
    cp = CasePaths("c1", cases_dir=tmp_path / "cases")
    d = cp.extracted_dir / "attachments"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data)
    return cp, d / name


def test_every_file_of_a_big_kit_is_analysed(tmp_path: Path) -> None:
    cp, z = _case(tmp_path, "kit.zip", _ms().many_files_zip(80))
    res = nested.scan_children([{"path": str(z), "filename": "kit.zip"}], cp)
    kids = res["tree"][0]["children"]
    assert len(kids) == 80
    assert not any(k.get("listed_only") for k in kids) and "listed_children" not in res["tree"][0]
    assert all(k.get("read_as") == "text" for k in kids)


def test_fifteen_archives_deep(tmp_path: Path) -> None:
    cp, z = _case(tmp_path, "factura.zip", _ms().deep_nesting_zip())
    res = nested.scan_children([{"path": str(z), "filename": "factura.zip"}], cp)
    nodes = list(_walk(res["tree"]))
    js = [(n, d) for n, d in nodes if n["filename"] == "Factura_0187.js"]
    assert js and js[0][1] == 16                       # factura.zip + 14 pago_N.zip + the script
    assert not any(n.get("listed_only") or n.get("truncated_children") for n, _ in nodes)
    rules = {f["rule"] for f in js[0][0]["findings"]}
    assert "js_wscript_shell" in rules
    text = " ".join(s.get("text", "") for s in res["ioc_sources"])
    assert "billing-portal.example/deep/stage11.ps1" in text


def test_a_file_inside_itself_is_not_opened_again(tmp_path: Path) -> None:
    import hashlib
    data = _ms().deep_nesting_zip(3)
    cp, z = _case(tmp_path, "factura.zip", data)
    ctx = {"_ancestors": [hashlib.sha256(data).hexdigest()]}  # as if an ancestor were this same file
    node = nested._scan_one(z, "factura.zip", paths=cp, depth=2, chain="x.zip", ctx=ctx)
    assert node.get("recursive") and not node["children"] and node.get("view_id")
    assert ctx["_ancestors"] == [hashlib.sha256(data).hexdigest()]   # the branch's stack is restored
