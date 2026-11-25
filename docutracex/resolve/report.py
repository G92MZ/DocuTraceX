"""One evaluator run as the engines report it: stages, findings and the Resolution summary.

Shared by every language: ``run(resolve_fn, code, loc, rule_prefix)`` returns ``{"stages"}`` (the
engines' ``decoded_stages`` shape), ``{"findings"}`` (the stages resolved, downloads, dynamic calls
not resolved) and ``{"summary"}`` (``scripts[i]["resolution"]``: what the Resolution tab shows), and
``merge`` puts the stages in front of an engine's own, keeping the engine's recipe when both found
the same stage.
"""

from __future__ import annotations

from typing import Any, Callable

from . import transforms


def run(resolve: Callable[..., Any], code: str, loc: str, prefix: str, alt: str | None = None) -> dict[str, Any] | None:
    try:
        sinks = resolve(code, loc)
        if alt and not sinks.stages and not sinks.downloads:
            sinks = resolve(alt, loc)
    except Exception as exc:  # noqa: BLE001  (an extra: the rest of the analysis stands)
        return {"stages": [], "findings": [], "summary": {"error": str(exc)[:300]}}
    stages = sinks.decoded_stages()
    findings = sinks.findings(loc)
    rows = []
    for st in sinks.stages:
        raw = st.data if isinstance(st.data, bytes) else st.data.encode("utf-8", "replace")
        rows.append({"kind": st.kind, "sink": st.sink, "recipe": list(st.recipe), "size": len(raw),
                     "sha256": st.sha256,
                     "type": transforms.magic(raw) or ("text" if isinstance(st.data, str) or transforms.is_text(raw) else "data"),
                     "line": st.line, "depth": st.depth, **({"target": st.target} if st.target else {})})
    if rows:
        binaries = [r for r in rows if r["type"] in ("pe", "elf", "zip", "macho") or r["kind"] == "load"]
        codes = [r for r in rows if r["kind"] == "exec"]
        detail = (f"resolved statically: {len(codes)} code stage(s) and {len(binaries)} binary stage(s) "
                  "(→ Nested, each with its recipe)")
        ev = "\n".join(f"{r['sink']}: {r['size']} bytes {r['type']} · {' → '.join(r['recipe'])}" for r in rows[:10])
        findings.insert(0, {"rule": f"{prefix}_resolved_stages", "severity": "high" if binaries else "medium",
                            "detail": detail, "evidence": ev})
    summary = {"stages": rows, "downloads": sinks.downloads, "unresolved": sinks.unresolved,
               "steps": sinks.steps[:600], "errors": getattr(sinks, "errors", [])[:40],
               "stats": getattr(sinks, "stats", {})}
    if not rows and not sinks.downloads and not sinks.unresolved:
        return {"stages": [], "findings": [], "summary": summary}
    return {"stages": stages, "findings": findings, "summary": summary}


def merge(mine: list[dict[str, Any]], theirs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The evaluator's stages first; the same stage found by the engine keeps the engine's recipe."""
    def key(st: dict[str, Any]) -> Any:
        return st.get("text") or st.get("data_b64")
    old = {key(st): st for st in theirs}
    seen = set()
    out = []
    for st in mine:
        k = key(st)
        if k and k not in seen:
            seen.add(k)
            out.append(old.get(k, st))
    return out + [st for st in theirs if key(st) not in seen]
