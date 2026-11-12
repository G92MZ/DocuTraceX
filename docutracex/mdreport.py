"""The whole analysis of a case as Markdown, one section per part — to paste or
attach into any LLM (or a ticket) when the AI tab is not connected.

Same content the AI tools read (``ai_tools``), written out in full: findings
with marks, IOCs, the stages of Nested, everything decrypted, the code
(functions by priority and the pseudocode of the decompiled ones), .NET
methods, ML, C2, network checks and every module's raw result. Each section is
bounded so a huge case still opens in the browser.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from . import ai_tools
from .storage import read_json

MAX_SECTION = 400_000          # characters per section
MAX_MODULE = 80_000            # per raw module in "Modules"
PSEUDOCODE_FUNCS = 25          # decompiled functions written out per binary


def _md(s: Any) -> str:
    return str("" if s is None else s).replace("|", "\\|").replace("\n", " ").strip()


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_(none)_\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_md(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def _fence(text: str, lang: str = "") -> str:
    t = str(text or "")
    fence = "````" if "```" in t else "```"
    return f"{fence}{lang}\n{t}\n{fence}\n"


def _cap(text: str, n: int = MAX_SECTION) -> str:
    return text if len(text) <= n else text[:n] + f"\n\n_… section truncated ({len(text) - n} more characters)_\n"


# --- sections ---------------------------------------------------------------------
def _summary(cid: str) -> str:
    s = ai_tools.case_summary(cid)
    h = s.get("hashes") or {}
    det = s.get("detected") or {}
    lines = [f"# Case {cid}", "", f"- **File:** {s.get('file')} ({s.get('size_bytes')} bytes)",
             f"- **Detected:** {det.get('name') or ''} ({det.get('mime') or ''}) · declared `{s.get('declared_extension')}` · {det.get('match') or ''}",
             *[f"- **{k.upper()}:** `{v}`" for k, v in h.items() if v],
             f"- **State:** {s.get('state')}", f"- **Counts:** {json.dumps(s.get('counts') or {})}",
             f"- **Modules:** {', '.join(s.get('modules_run') or [])}", "", "## Steps", "",
             _table(["Step", "Status", "Findings", "Note"],
                    [[x.get("step"), x.get("status"), x.get("findings"), x.get("note")] for x in s.get("steps") or []])]
    return "\n".join(lines)


def _findings(cid: str) -> str:
    from . import marks as marks_service
    paths = ai_tools._paths(cid)
    items = marks_service.apply(marks_service.case_findings(paths), marks_service.read_marks(paths))["findings"]
    items = sorted(items, key=lambda f: ai_tools._SEV_ORDER.get(f.get("severity"), 9))
    rows = [[f.get("severity"), (f.get("mark") or {}).get("state", "unreviewed"), f.get("source"), f.get("rule"),
             ai_tools._clip(f.get("detail"), 500), ai_tools._clip(f.get("location"), 200),
             ai_tools._clip(f.get("evidence"), 600), (f.get("mark") or {}).get("comment") or ""] for f in items]
    return f"# Findings ({len(items)})\n\n" + _table(
        ["Severity", "Mark", "Source", "Rule", "Detail", "Location", "Evidence", "Analyst comment"], rows)


def _iocs(cid: str) -> str:
    paths = ai_tools._paths(cid)
    items = (read_json(paths.subresult("iocs")) or {}).get("iocs", [])
    def tag(i: dict[str, Any]) -> str:
        if i.get("tenant"):
            return f"tenant {i['tenant'].get('name', '')}: {i['tenant'].get('why', '')}"
        return f"RMM: {i['rmm'].get('product', '')}" if i.get("rmm") else ""
    rows = [[i.get("type"), i.get("value"), i.get("count"),
             "; ".join(sorted({f"{o.get('module')}/{o.get('location')}" for o in i.get("occurrences", [])})[:4]), tag(i)]
            for i in items]
    return f"# IOCs ({len(items)})\n\n" + _table(["Type", "Value", "Count", "Seen in", "Tag"], rows)


def _nested(cid: str) -> str:
    tree = ai_tools.get_nested_tree(cid, 12)["tree"]
    out = ["# Nested: extracted, unpacked, hidden and decrypted stages", ""]

    def walk(nodes: list[dict[str, Any]], d: int) -> None:
        for n in nodes:
            extra = []
            if n.get("obtained"):
                extra.append(f"obtained: {n['obtained']}")
            if n.get("recipe"):
                extra.append(f"recipe: `{n['recipe']}`")
            if n.get("hidden_payload"):
                hp = n["hidden_payload"]
                extra.append(f"hides a {hp.get('kind')} ({hp.get('how')})")
            out.append(f"{'  ' * d}- **{n.get('file')}** · {n.get('kind')} {n.get('format') or ''} · "
                       f"sha256 `{n.get('sha256')}…` · {n.get('findings')} finding(s), {n.get('high')} high"
                       + (" · " + " · ".join(extra) if extra else ""))
            walk(n.get("children") or [], d + 1)
    walk(tree, 0)
    return "\n".join(out) + ("\n" if tree else "_(no children)_\n")


def _decrypted(cid: str) -> str:
    items = ai_tools.get_decrypted(cid, 200)["items"]
    return "# Decrypted / decoded statically\n\n" + _table(
        ["Kind", "Where", "Plain", "How", "Routine", "Used by / recipe"],
        [[x.get("kind"), x.get("where"), x.get("plain"), x.get("how"), x.get("routine"),
          x.get("used_by") or x.get("recipe")] for x in items])


def _code(cid: str) -> str:
    from .codeanalysis import case as code_case
    paths = ai_tools._paths(cid)
    lab = ai_tools._labels(paths)
    out = ["# Code analysis (native / Go)", ""]
    files = ai_tools._code_files(paths)
    if not files:
        return out[0] + "\n\n_(no binary analysed as code)_\n"
    for sha, mode, f in files:
        full = read_json(f) or {}
        fns = full.get("functions") or []
        out += [f"## {lab.get(sha) or sha[:16]} ({'Go' if mode == 'go' else 'native'})", "",
                f"sha256 `{sha}` · {len(fns)} functions · {sum(1 for x in fns if x.get('decompiled'))} decompiled", ""]
        sm = full.get("summary") or {}
        if sm:
            out += [_fence(json.dumps(sm, ensure_ascii=False, indent=1, default=str)[:4000], "json")]
        out += ["### Functions by priority", "",
                _table(["#", "Function", "Address", "Score", "Behaviour", "Size", "Why"],
                       [[x.get("rank"), x.get("name"), hex(x["addr"]), x.get("score"), ", ".join(x.get("categories") or []),
                         x.get("size"), "; ".join((x.get("reasons") or [])[:3])] for x in fns[:150]])]
        caps = (full.get("capabilities") or {}).get("items") or (full.get("capabilities") or {}).get("capabilities") or []
        if caps:
            out += ["### Capabilities", "", _fence(json.dumps(caps, ensure_ascii=False, default=str)[:20000], "json")]
        crypto = full.get("crypto") or {}
        if crypto:
            out += ["### Crypto", "", _fence(json.dumps(crypto, ensure_ascii=False, default=str)[:20000], "json")]
        out += ["### Pseudocode of the decompiled functions (by priority)", ""]
        n = 0
        for x in fns:
            if n >= PSEUDOCODE_FUNCS:
                break
            dec = (full.get("decompiled") or {}).get(str(x["addr"])) or {}
            if dec.get("status") != "ok" or not dec.get("code"):
                continue
            v = code_case.function_view(full, x["addr"]) or {}
            n += 1
            out += [f"#### {x.get('name')} @ {hex(x['addr'])} — {', '.join(x.get('categories') or []) or 'no category'}", "",
                    f"callers: {', '.join(c['name'] for c in (v.get('callers') or [])[:15]) or '—'}  ",
                    f"calls: {', '.join([c['name'] for c in (v.get('callees') or [])[:15]] + (v.get('callee_names') or [])[:15]) or '—'}", "",
                    _fence(dec["code"][:30000], "c")]
        if not n:
            out += ["_(no function decompiled: use Code → Decompile all, then regenerate)_", ""]
    return _cap("\n".join(out))


def _dotnet(cid: str) -> str:
    paths = ai_tools._paths(cid)
    objs = [o for o in (read_json(paths.subresult("dotnet")) or {}).get("objects") or []
            if o.get("result") and not o["result"].get("error") and not o.get("duplicate")]
    if not objs:
        return "# .NET\n\n_(no .NET assembly)_\n"
    out = ["# .NET assemblies", ""]
    for o in objs:
        r = o["result"]
        a = r.get("assembly") or {}
        cil = r.get("cil") or {}
        out += [f"## {o.get('label')} — {a.get('name')} {a.get('version')}", "",
                f"- runtime {r.get('runtime')} · entry `{r.get('entry_point')}` · obfuscators: "
                f"{', '.join(x['name'] for x in r.get('obfuscators') or []) or 'none'} · traits: {'; '.join(r.get('traits') or [])}",
                f"- references: {', '.join(x['name'] for x in r.get('references') or [])}", "",
                "### Methods of interest", "",
                _table(["Method", "Behaviour", "Calls", "Strings", "Static arrays"],
                       [[m.get("method"), ", ".join(m.get("categories") or []), ", ".join((m.get("calls") or [])[:12]),
                         " · ".join((m.get("strings") or [])[:8]), " · ".join(m.get("arrays") or [])]
                        for m in (cil.get("interesting") or [])[:120]]),
                "### Strings decrypted statically", "",
                _table(["Plain", "Encrypted", "Decryptor", "Caller", "How"],
                       [[d.get("output"), ai_tools._clip(d.get("input"), 120), d.get("decryptor"), d.get("caller"), d.get("how")]
                        for d in cil.get("decrypted") or []]),
                "### P/Invoke and framework APIs", "",
                _table(["Kind", "Name", "Behaviour"],
                       [["P/Invoke", f"{p.get('dll')}!{p.get('entry')}", ", ".join(p.get("categories") or [])] for p in r.get("pinvoke") or []]
                       + [["API", x.get("type"), f"{x.get('label')}: {', '.join(x.get('members') or [])}"] for x in r.get("apis") or []]),
                "### Resources", ""]
        for x in r.get("resources") or []:
            extra = []
            if x.get("decrypted"):
                extra.append(f"decrypted → {x['decrypted'].get('type')} ({x['decrypted'].get('how')})")
            out.append(f"- `{x.get('name')}` {x.get('size')} bytes, entropy {x.get('entropy')}" + (" · " + "; ".join(extra) if extra else ""))
            for e in x.get("entries") or []:
                out.append(f"  - {e.get('name')} ({e.get('type')}, {e.get('size')})"
                           + (f" = {ai_tools._clip(e.get('value'), 300)}" if e.get("value") else "")
                           + (f" · hidden {e['stego'].get('type')} in pixels ({e['stego'].get('how')})" if e.get("stego") else ""))
        out += ["", "### User strings (#US)", "", _fence("\n".join((r.get("strings") or [])[:3000]))]
    return _cap("\n".join(out))


def _ml(cid: str) -> str:
    ml = ai_tools.get_ml(cid)
    out = ["# Machine Learning (EMBER2024)", "", f"_{ml.get('note')}_", ""]
    ch = ml.get("chain")
    if ch:
        out += [f"**Highest score of the case:** {ch.get('max_score')} — {ch.get('object')}"
                + (" (from a stage, not the original)" if ch.get("from_stage") else ""), ""]
    out.append(_table(["Object", "Model", "Score", "Verdict", "Unusual for model", "Top features", "Family guess"],
                      [[x["object"], x["model"], x["score"], x["verdict"], "yes" if x.get("unusual_for_model") else "",
                        "; ".join(x.get("top_features") or []), ", ".join(f"{n} ({c})" for n, c in x.get("family_guess") or [])]
                       for x in ml.get("items") or []]))
    sims = [(x["object"], s) for x in ml.get("items") or [] for s in x.get("similar") or []]
    out += ["## Similar objects in other cases", "",
            _table(["Object", "Similarity", "Case", "Other object", "Same file"],
                   [[o, s.get("similarity"), s.get("case"), s.get("object"), "yes" if s.get("same_file") else ""] for o, s in sims])]
    return "\n".join(out)


def _c2(cid: str) -> str:
    paths = ai_tools._paths(cid)
    c2 = read_json(paths.subresult("c2")) or {}
    cfgs = c2.get("configs") or []
    out = [f"# C2 / beacon configurations ({len(cfgs)})", ""]
    from .c2 import families
    about = families.markdown([c.get("family") or "" for c in cfgs])
    if about:
        out += [about, ""]
    for c in cfgs:
        out += [f"## {c.get('family')} ({c.get('kind')}) — {c.get('object')}", "",
                f"- status: {c.get('status') or 'configuration'} · method: {c.get('method')} · confidence: {c.get('confidence')}",
                f"- C2: {', '.join(c.get('c2') or []) or '—'}",
                f"- run: {c.get('run_id') or '—'} · RAW: {c.get('raw_ref') or '—'}"]
        for r in c.get("related") or []:
            out.append(f"- related: case {r.get('case')} {r.get('object', '')} — {r.get('match')} ({r.get('strength')})")
        norm = c.get("normalized") or []
        if norm:
            out += ["", "| field | value | status | read by | confidence |", "|---|---|---|---|---|"]
            out += [f"| {n['name']} | {str(n['value']).replace('|', '/')[:200]} | {n['status']} | {n['extractor']} | {n['confidence']} |"
                    for n in norm[:300]]
        out += ["", _fence(json.dumps({"summary": c.get("summary"), "sections": c.get("sections"),
                                       "fields": c.get("fields")}, ensure_ascii=False,
                                      indent=1, default=str)[:20000], "json")]
    for pr in c2.get("protected") or []:
        out += ["", f"- **protected** — {pr.get('object')}: "
                + ", ".join(f"{x.get('name')} ({x.get('evidence')})" for x in pr.get("protectors") or [])
                + f". {pr.get('note', '')}"]
    if not cfgs:
        out.append("_(no configuration found, or C2 not run)_")
    return "\n".join(out)


def _network(cid: str) -> str:
    return "# Network checks\n\n" + _fence(json.dumps(ai_tools.get_network_checks(cid), ensure_ascii=False,
                                                       indent=1, default=str)[:MAX_SECTION], "json")


def _modules(cid: str) -> str:
    paths = ai_tools._paths(cid)
    out = ["# Raw module results", "",
           "_Every module's JSON result, as stored (long ones truncated). The sections above are the readable view._", ""]
    for p in sorted(paths.results_dir.glob("*.json")):
        if p.stem in ("summary", "findings"):
            continue
        try:
            text = json.dumps(json.loads(p.read_text(encoding="utf-8")), ensure_ascii=False, indent=1, default=str)
        except (OSError, ValueError):
            continue
        out += [f"## {p.stem}", "", _fence(text[:MAX_MODULE] + (f"\n… (+{len(text) - MAX_MODULE} chars)" if len(text) > MAX_MODULE else ""), "json")]
    return _cap("\n".join(out), MAX_SECTION * 3)


def _yara(cid: str) -> str:
    paths = ai_tools._paths(cid)
    y = read_json(paths.subresult("yara")) or {}
    out = ["# YARA", ""]
    if not y:
        return "\n".join(out + ["_(YARA not run on this case)_"])
    out.append(f"{y.get('rule_count', 0)} rule(s) · {y.get('files_scanned', 0)} object(s) scanned · "
               f"{y.get('match_count', 0)} match(es). Hits are triage leads: they become findings once marked.")
    rows = []
    for h in y.get("scanned") or []:
        for m in h.get("matches") or []:
            meta = m.get("meta") or {}
            strings = "; ".join(f"{x.get('id')}@{x.get('offset')}: {str(x.get('text', ''))[:40]}"
                                for x in (m.get("strings") or [])[:5])
            rows.append([m.get("rule"), h.get("file"), meta.get("description") or meta.get("desc") or "",
                         ", ".join(m.get("tags") or []), strings])
    out += ["", _table(["rule", "object", "description", "tags", "matched strings"], rows)]
    if y.get("errors"):
        out += ["", "**Rule errors:**", ""] + [f"- {_md(e)}" for e in y["errors"][:50]]
    return _cap("\n".join(out), MAX_SECTION)


def _rmm(cid: str) -> str:
    paths = ai_tools._paths(cid)
    r = read_json(paths.subresult("rmm")) or {}
    c2 = read_json(paths.subresult("c2")) or {}
    out = ["# RMM / remote-access tools", ""]
    if not r and not c2:
        return "\n".join(out + ["_(not run on this case)_"])
    out.append(f"Product list: {r.get('source', 'built-in')} ({r.get('products', '?')} products). "
               "Legitimate software: who deployed it, and to whose instance it connects, decides.")
    cfgs = list(r.get("configs") or []) + [x for x in c2.get("configs") or [] if str(x.get("family", "")).startswith("RMM: ")]
    from .c2 import families
    about = families.markdown([c.get("family") or "" for c in cfgs])
    if about:
        out += ["", about]
    rows = [[c.get("family", "")[5:], c.get("kind"), ", ".join((c.get("summary") or {}).get("C2") or []) or "—",
             c.get("object", ""), ", ".join(f"{k}: {v}" for k, v in (c.get("fields") or {}).items())[:300]] for c in cfgs]
    out += ["", "## Products in the objects", "", _table(["product", "kind", "instance", "object", "settings"], rows)]
    ms = r.get("mentions") or []
    out += ["## Named in the text", "", _table(["product", "severity", "why", "where", "context"],
                                               [[m.get("product"), m.get("severity"), m.get("why"), m.get("location"),
                                                 str(m.get("snippet", ""))[:200]] for m in ms])]
    iocs = read_json(paths.subresult("iocs")) or {}
    tagged = [i for i in iocs.get("iocs") or [] if i.get("rmm")]
    out += ["## IOCs of a product", "", _table(["type", "value", "product", "why"],
                                               [[i["type"], i["value"], i["rmm"].get("product"), i["rmm"].get("why")]
                                                for i in tagged[:300]])]
    return _cap("\n".join(out), MAX_SECTION)


SECTIONS: list[tuple[str, str, Callable[[str], str]]] = [
    ("summary", "Summary", _summary), ("findings", "Findings", _findings), ("iocs", "IOCs", _iocs),
    ("nested", "Nested / stages", _nested), ("decrypted", "Decrypted", _decrypted), ("code", "Code", _code),
    ("dotnet", ".NET", _dotnet), ("ml", "Machine Learning", _ml), ("yara", "YARA", _yara), ("c2", "C2", _c2),
    ("rmm", "RMM / remote access", _rmm),
    ("network", "Network checks", _network), ("modules", "Raw modules", _modules),
]


def build(case_id: str) -> list[dict[str, Any]]:
    """[{id, title, markdown, chars}] — a failing section says so instead of breaking the rest."""
    ai_tools._paths(case_id)
    out = []
    for sid, title, fn in SECTIONS:
        try:
            md = fn(case_id)
        except Exception as exc:  # noqa: BLE001
            md = f"# {title}\n\n_(could not build this section: {exc})_\n"
        out.append({"id": sid, "title": title, "markdown": md, "chars": len(md)})
    return out


def full(case_id: str) -> str:
    head = ("<!-- DocuTraceX case export (Markdown). Static analysis results; findings are not verdicts until "
            "marked by the analyst. -->\n\n")
    return head + "\n\n---\n\n".join(s["markdown"] for s in build(case_id))
