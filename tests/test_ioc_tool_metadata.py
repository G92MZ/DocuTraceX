"""Tool bookkeeping is no indicator: the family-YARA rule sources' URLs (C2 tab), a PDF's
trailer /ID, peepdf's report of the PDF's own MD5 / SHA-1 / SHA-256 and /IDs, and the
hashes of files found inside the case. Real indicators next to them are still mined."""

from __future__ import annotations

import hashlib
import json

from docutracex import ioc


def _h(alg: str, seed: str) -> str:                        # inert, realistic-looking values
    return hashlib.new(alg, seed.encode()).hexdigest()


ID1, ID2 = _h("md5", "trailer-id-1"), _h("md5", "trailer-id-2")    # a trailer /ID pair (MD5-shaped)
PDF_MD5, PDF_SHA1, PDF_SHA256 = _h("md5", "pedido.pdf"), _h("sha1", "pedido.pdf"), _h("sha256", "pedido.pdf")
REAL_HASH = _h("sha256", "factura-loader.exe")                       # a payload hash the document names


def _values(modules: dict, kind: str | None = None) -> set[str]:
    got = ioc.extract(ioc.sources_from_modules(modules))
    return {i["value"].lower() for i in got["iocs"] if kind is None or i["type"] == kind}


def test_family_yara_sources_are_not_iocs() -> None:
    c2 = {"family_yara": {"sources": [{"name": "CAPE", "url": "https://github.com/kevoreilly/CAPEv2/tree/master/data/yara/CAPE"},
                                      {"name": "ditekSHen", "url": "https://github.com/ditekshen/detection/tree/master/yara"}],
                          "matches": [{"rule": "Lumma", "family": "Lumma"}]},
          "configs": [{"family": "Lumma", "c2": ["https://facturas-cdn.example/gate.php"]}]}
    got = _values({"c2": c2})
    assert not any("github.com" in v for v in got)
    assert any("facturas-cdn.example" in v for v in got)


def test_pdf_trailer_id_and_peepdf_own_hashes_are_not_iocs() -> None:
    snippet = (f"<< /Type /XRef /Size 30 /Root 1 0 R /ID [<{ID1}> <{ID2.upper()}>] >>\n"
               f"payload sha256 {REAL_HASH} from https://pagos-cdn.example/f.exe")
    peepdf = {"peepdf_analysis": {
        "basic": {"md5": PDF_MD5, "sha1": PDF_SHA1, "sha256": PDF_SHA256, "ids": {"version_0": f"{ID1} {ID2}"},
                  "filename": "pedido.pdf", "num_objects": 30},
        "advanced": [{"version_info": {"suspicious_elements": {"urls": ["https://pagos-cdn.example/landing"]}}}],
        "peepdf_info": {"url": "https://github.com/digitalsleuth/peepdf-3"}}}
    modules = {"pdf": {"objects": [{"id": 5, "snippet": snippet}]},
               "pdftools": {"tools": {"peepdf": {"output": json.dumps(peepdf, indent=4)}}}}
    hashes = _values(modules, "hash_like")
    assert hashes == {REAL_HASH}                            # the /IDs and the PDF's own hashes are gone
    urls = _values(modules)
    assert any("pagos-cdn.example/landing" in v for v in urls)   # peepdf's URLs are still mined
    assert any("pagos-cdn.example/f.exe" in v for v in urls)


def test_hashes_of_files_inside_the_case_are_dropped(tmp_path) -> None:  # noqa: ANN001
    from docutracex.analyze import _drop_own_hashes
    from docutracex.storage import CasePaths, write_subresult
    (tmp_path / "c1").mkdir()
    paths = CasePaths("c1", cases_dir=tmp_path)
    paths.manifest.parent.mkdir(parents=True, exist_ok=True)
    top = _h("sha256", "factura.eml")
    paths.manifest.write_text(json.dumps({"original": {"hashes": {"sha256": top}}}))
    child = _h("sha256", "pedido.pdf")
    write_subresult(paths, "nested", {"tree": {"sha256": top, "children": [{"name": "pedido.pdf", "sha256": child}]}})
    res = {"iocs": [{"type": "hash_like", "value": child}, {"type": "hash_like", "value": REAL_HASH},
                    {"type": "hash_like", "value": top}]}
    _drop_own_hashes(paths, res)
    assert [i["value"] for i in res["iocs"]] == [REAL_HASH]
