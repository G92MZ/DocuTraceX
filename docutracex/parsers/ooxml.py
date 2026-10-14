"""Common OOXML engine.

Shared by modern Word/Excel/PowerPoint (and used for the OPC side of XLSB). It
opens the ZIP/OPC package, inventories parts, parses ``[Content_Types].xml`` and
relationships, flags anomalies, hashes each part, and extracts media/embedded
binaries (identified with libmagic). It never executes content and does not
resolve external XML entities or fetch anything over the network.

Deep analysis of nested packages/objects is NOT started automatically; extracted
components are inventoried for a later, explicit analysis.
"""

from __future__ import annotations

import hashlib
import posixpath
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as _ET

try:
    from defusedxml.ElementTree import fromstring as _safe_fromstring
    _XML_SAFE = True
except Exception:  # noqa: BLE001  (fallback if defusedxml missing)
    _XML_SAFE = False

    def _safe_fromstring(data: bytes):  # type: ignore
        # Fallback: stdlib parser. Still does not fetch external resources by
        # default, but defusedxml is preferred and reported in diagnostics.
        return _ET.fromstring(data)

CT_NS = "{http://schemas.openxmlformats.org/package/2006/content-types}"
REL_NS = "{http://schemas.openxmlformats.org/package/2006/relationships}"

# Where binary media / embedded objects typically live inside OOXML packages.
_MEDIA_HINTS = ("/media/", "/embeddings/", "/fonts/")


def _norm(path: str) -> str:
    """Normalise an internal part path to a stable id: forward slashes, a single
    leading slash, no '.' or '..' segments. Accepts paths with or without a
    leading slash (OPC PartName values already start with '/')."""
    p = path.replace("\\", "/").lstrip("/")
    return posixpath.normpath("/" + p)


def _is_dangerous(name: str) -> bool:
    n = name.replace("\\", "/")
    if n.startswith("/") or ".." in n.split("/"):
        return True
    # Windows drive / UNC-looking entries.
    if len(n) >= 2 and n[1] == ":":
        return True
    return False


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_content_types(zf: zipfile.ZipFile, anomalies: list[dict]) -> tuple[dict, dict]:
    """Return (defaults {ext: ct}, overrides {partname: ct})."""
    defaults: dict[str, str] = {}
    overrides: dict[str, str] = {}
    try:
        raw = zf.read("[Content_Types].xml")
    except KeyError:
        anomalies.append({"kind": "missing_content_types",
                          "detail": "[Content_Types].xml not found"})
        return defaults, overrides
    try:
        root = _safe_fromstring(raw)
    except Exception as exc:  # noqa: BLE001
        anomalies.append({"kind": "malformed_xml", "part": "[Content_Types].xml",
                          "detail": str(exc)})
        return defaults, overrides
    for el in root:
        if el.tag == f"{CT_NS}Default":
            ext = (el.get("Extension") or "").lower()
            if ext:
                defaults[ext] = el.get("ContentType") or ""
        elif el.tag == f"{CT_NS}Override":
            part = _norm(el.get("PartName") or "")
            overrides[part] = el.get("ContentType") or ""
    return defaults, overrides


def _resolve_ct(part: str, defaults: dict, overrides: dict) -> str | None:
    if part in overrides:
        return overrides[part]
    ext = part.rsplit(".", 1)[-1].lower() if "." in part else ""
    return defaults.get(ext)


def _parse_relationships(zf: zipfile.ZipFile, anomalies: list[dict]) -> list[dict]:
    """Parse every *.rels file. Returns a list of relationship dicts."""
    rels: list[dict] = []
    for name in zf.namelist():
        if not name.endswith(".rels"):
            continue
        source_dir = posixpath.dirname(posixpath.dirname(name))  # _rels is under the part's dir
        try:
            root = _safe_fromstring(zf.read(name))
        except Exception as exc:  # noqa: BLE001
            anomalies.append({"kind": "malformed_xml", "part": name, "detail": str(exc)})
            continue
        for el in root:
            if el.tag != f"{REL_NS}Relationship":
                continue
            target = el.get("Target") or ""
            mode = el.get("TargetMode") or "Internal"
            resolved = None
            if mode != "External":
                base = "/" + source_dir if source_dir else ""
                resolved = _norm(posixpath.join(base, target))
            rels.append({
                "rels_file": name,
                "id": el.get("Id"),
                "type": el.get("Type"),
                "target": target,
                "mode": mode,
                "resolved_target": resolved,
            })
    return rels


def analyze(original_path: Path, extracted_dir: Path) -> dict[str, Any]:
    """Analyze an OOXML/OPC package. Returns the module sub-result."""
    result: dict[str, Any] = {
        "module": "ooxml",
        "xml_safe": _XML_SAFE,
        "status": "ok",
        "components": [],
        "relationships": [],
        "anomalies": [],
        "extracted": [],
        "counts": {},
    }
    anomalies: list[dict] = result["anomalies"]

    if not zipfile.is_zipfile(original_path):
        result["status"] = "error"
        anomalies.append({"kind": "not_a_zip", "detail": "File is not a valid ZIP/OPC package"})
        return result

    with zipfile.ZipFile(original_path) as zf:
        names = zf.namelist()

        # Duplicate entries (zip can hold repeated names).
        seen: set[str] = set()
        for n in names:
            if n in seen:
                anomalies.append({"kind": "duplicate_zip_entry", "part": n})
            seen.add(n)

        defaults, overrides = _parse_content_types(zf, anomalies)
        rels = _parse_relationships(zf, anomalies)
        result["relationships"] = rels

        present_parts: set[str] = set()
        for info in zf.infolist():
            if info.is_dir():
                continue
            raw_name = info.filename
            if _is_dangerous(raw_name):
                anomalies.append({"kind": "dangerous_path", "part": raw_name})
                continue
            part = _norm(raw_name)
            present_parts.add(part)
            data = zf.read(info.filename)
            ct = _resolve_ct(part, defaults, overrides)
            is_xml = part.endswith(".xml") or part.endswith(".rels")
            comp: dict[str, Any] = {
                "id": part,
                "path": part,
                "content_type": ct,
                "size_bytes": info.file_size,
                "compressed_bytes": info.compress_size,
                "sha256": _sha256_bytes(data),
                "is_xml": is_xml,
            }
            if ct is None and part not in ("/[Content_Types].xml",):
                anomalies.append({"kind": "no_content_type", "part": part})
            # Validate XML parts parse.
            if is_xml and part != "/[Content_Types].xml":
                try:
                    _safe_fromstring(data)
                except Exception as exc:  # noqa: BLE001
                    anomalies.append({"kind": "malformed_xml", "part": part, "detail": str(exc)})
                    comp["xml_malformed"] = True
            # Extract media / embedded binaries to the isolated workspace.
            if (any(h in part for h in _MEDIA_HINTS)) and not is_xml:
                rel = part.lstrip("/")
                dest = extracted_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                ident = _identify(dest, part)
                result["extracted"].append({
                    "id": part,
                    "stored_path": str(dest.relative_to(extracted_dir.parent).as_posix()),
                    "sha256": comp["sha256"],
                    "size_bytes": info.file_size,
                    "detected_mime": ident.get("mime"),
                    "detected_name": ident.get("name"),
                })
            result["components"].append(comp)

        # Broken internal relationship targets.
        for r in rels:
            rt = r.get("resolved_target")
            if r["mode"] != "External" and rt and rt not in present_parts:
                anomalies.append({"kind": "broken_relationship_target",
                                  "rels_file": r["rels_file"], "target": r["target"]})

    external = [r for r in rels if r["mode"] == "External"]
    for r in external:
        anomalies.append({"kind": "external_relationship", "target": r["target"],
                          "type": r.get("type")})

    result["counts"] = {
        "components": len(result["components"]),
        "relationships": len(rels),
        "external_relationships": len(external),
        "extracted": len(result["extracted"]),
        "anomalies": len(anomalies),
    }
    if anomalies and result["status"] == "ok":
        result["status"] = "ok_with_findings"
    return result


def _identify(path: Path, declared_part: str) -> dict[str, Any]:
    """Identify an extracted component with libmagic (best-effort)."""
    try:
        from .. import identify as _id
        return _id.identify(path, Path(declared_part).suffix.lower())
    except Exception:  # noqa: BLE001
        return {}
