"""QR / barcode reader for PDF pages and images (run as a separate process).

Renders PDF pages with pdfium (pypdfium2, no JavaScript) and decodes barcodes
with zxing-cpp. Rendering a hostile PDF is parser work on untrusted input, so
this runs in its own process with a time limit:

    python -m docutracex.parsers.pdf_qr <file> [max_pages]

and prints JSON: {"codes": [{"page", "format", "text"}], "pages": n, "error"}.
Plain images (PNG/JPEG/GIF/BMP...) are decoded directly.
"""

from __future__ import annotations

import json
import sys

MAX_PAGES = 15
SCALE = 2.0


def _decode(img) -> list[dict[str, str]]:
    import zxingcpp

    out = []
    for r in zxingcpp.read_barcodes(img):
        out.append({"format": str(r.format).split(".")[-1], "text": r.text})
    return out


def scan(path: str, max_pages: int = MAX_PAGES) -> dict:
    res: dict = {"codes": [], "pages": 0, "error": None}
    with open(path, "rb") as fh:
        head = fh.read(8)
    try:
        if head.startswith(b"%PDF") or b"%PDF" in head:
            import pypdfium2 as pdfium

            pdf = pdfium.PdfDocument(path)
            try:
                res["pages"] = len(pdf)
                for i in range(min(len(pdf), max_pages)):
                    page = pdf[i]
                    img = page.render(scale=SCALE).to_pil()
                    for c in _decode(img):
                        res["codes"].append({"page": i + 1, **c})
                    page.close()
            finally:
                pdf.close()
        else:
            from PIL import Image

            with Image.open(path) as img:
                img.load()
                for c in _decode(img.convert("RGB")):
                    res["codes"].append({"page": 0, **c})
    except Exception as exc:  # noqa: BLE001
        res["error"] = str(exc)
    return res


def main(argv: list[str]) -> int:
    if not argv:
        print(json.dumps({"error": "usage: pdf_qr <file> [max_pages]"}))
        return 2
    max_pages = int(argv[1]) if len(argv) > 1 else MAX_PAGES
    print(json.dumps(scan(argv[0], max_pages)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
