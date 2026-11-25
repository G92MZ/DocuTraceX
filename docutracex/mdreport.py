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
from pathlib import Path
from typing import Any, Callable

from . import ai_tools
from .storage import read_json

# No size limits: this export is read by an LLM (or attached to a ticket) as the whole analysis —
# to find what a tool showed and no rule detected. A case big enough to matter is better complete
# than cut. Only FLOSS's every-string list goes to a file of its own (the ZIP export); the report
# keeps the strings worth reading.
PSEUDOCODE_FUNCS = 10 ** 9     # every decompiled function


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


def _cap(text: str, n: int | None = None) -> str:
    """Kept for callers: sections are no longer truncated."""
    return text


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
             "; ".join(sorted({f"{o.get('module')}/{o.get('location')}" for o in i.get("occurrences", [])})), tag(i)]
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
            out += [_fence(json.dumps(sm, ensure_ascii=False, indent=1, default=str), "json")]
        out += ["### Functions by priority", "",
                _table(["#", "Function", "Address", "Score", "Behaviour", "Size", "Why"],
                       [[x.get("rank"), x.get("name"), hex(x["addr"]), x.get("score"), ", ".join(x.get("categories") or []),
                         x.get("size"), "; ".join(x.get("reasons") or [])] for x in fns])]
        caps = (full.get("capabilities") or {}).get("items") or (full.get("capabilities") or {}).get("capabilities") or []
        if caps:
            out += ["### Capabilities", "", _fence(json.dumps(caps, ensure_ascii=False, default=str), "json")]
        crypto = full.get("crypto") or {}
        if crypto:
            out += ["### Crypto", "", _fence(json.dumps(crypto, ensure_ascii=False, default=str), "json")]
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
                    f"callers: {', '.join(c['name'] for c in (v.get('callers') or [])) or '—'}  ",
                    f"calls: {', '.join([c['name'] for c in (v.get('callees') or [])] + (v.get('callee_names') or [])) or '—'}", "",
                    _fence(dec["code"], "c")]
        if not n:
            out += ["_(no function decompiled: use Code → Decompile all, then regenerate)_", ""]
    return "\n".join(out)


# --- every module result of the case, the nested children's included ----------------
def _module_results(paths) -> list[tuple[str, dict[str, Any]]]:  # noqa: ANN001
    """(label, result) of every module of the case and of every nested child's own analysis."""
    out: list[tuple[str, dict[str, Any]]] = []
    for p in sorted(paths.results_dir.glob("*.json")):
        if p.stem in ("summary", "findings", "iocs", "tasks"):
            continue
        r = read_json(p)
        if isinstance(r, dict):
            out.append((p.stem, r))
    views = sorted((paths.results_dir / "nested_views").glob("*.json")) if (paths.results_dir / "nested_views").is_dir() else []
    for p in views:
        v = read_json(p) or {}
        for name, r in sorted((v.get("modules") or {}).items()):
            if isinstance(r, dict):
                out.append((f"Nested › {v.get('chain') or v.get('filename')} › {name}", r))
    return out


def _read_rel(paths, rel: str | None) -> str | None:  # noqa: ANN001
    if not rel:
        return None
    try:
        p = (paths.root / rel).resolve()
        if paths.root.resolve() not in p.parents:
            return None
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _tool_records(obj: Any, path: str) -> list[tuple[str, dict[str, Any]]]:
    """Every external tool's record (its command, exit code, output, stderr) inside a result."""
    out: list[tuple[str, dict[str, Any]]] = []
    if isinstance(obj, dict):
        if isinstance(obj.get("output"), str) or ("returncode" in obj and ("command" in obj or "available" in obj)):
            out.append((path, obj))
            return out
        for k, v in obj.items():
            if not str(k).startswith("_"):
                out += _tool_records(v, f"{path} › {k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _tool_records(v, f"{path}[{i}]")
    return out


def _tools(cid: str) -> str:
    """Every tool's complete output — what an agent reads to find what a tool showed and no
    rule caught (the module results keep 60,000 characters; the rest is in results/tool_output)."""
    paths = ai_tools._paths(cid)
    out = ["# Tool outputs (complete)", "",
           "_Every external tool run on the case and on each nested child: command, exit code, time, "
           "error, stderr and the whole output, as the tool printed it._", ""]
    n = 0
    for label, res in _module_results(paths):
        for where, rec in _tool_records(res, label):
            n += 1
            full = _read_rel(paths, rec.get("output_full"))
            text = full if full is not None else str(rec.get("output") or "")
            err = _read_rel(paths, rec.get("stderr_full")) or rec.get("stderr")
            meta = [f"`{rec['command']}`" if rec.get("command") else "",
                    f"exit {rec['returncode']}" if rec.get("returncode") is not None else "",
                    f"{rec['duration_s']} s" if rec.get("duration_s") is not None else "",
                    "**timed out**" if rec.get("timed_out") else "",
                    f"output {len(text)} chars" + (" (complete; the tab shows the first 60,000)" if full else "")]
            out += [f"## {where}", "", " · ".join(m for m in meta if m), ""]
            if rec.get("error"):
                out += [f"**Error:** {_md(rec['error'])}", ""]
            out += [_fence(text) if text.strip() else "_(no output)_\n"]
            if err and str(err).strip():
                out += ["stderr:", "", _fence(str(err))]
    if not n:
        out.append("_(no external tool ran on this case)_")
    return "\n".join(out)


_RELEVANT = __import__("re").compile(
    r"(?i)(https?://|ftp://|\b(?:[a-z0-9-]+\.)+(?:com|net|org|info|biz|io|ru|cn|top|xyz|example|onion|php|exe|dll|ps1|bat|vbs|js)\b"
    r"|\b\d{1,3}(?:\.\d{1,3}){3}\b|[a-z]:\\|\\\\|%[a-z]+%|\bhk(?:lm|cu|ey_)|software\\|currentversion"
    r"|\b(?:cmd|powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript|schtasks|certutil|bitsadmin|wmic|vssadmin|bcdedit|net1?|reg)(?:\.exe)?\b"
    r"|\b(?:Virtual(?:Alloc|Protect)|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|SetWindowsHookEx|GetAsyncKeyState"
    r"|InternetOpen|URLDownloadToFile|WinHttp|HttpSendRequest|CryptDecrypt|CryptEncrypt|BCrypt|IsDebuggerPresent|ShellExecute|CreateProcess"
    r"|LoadLibrary|GetProcAddress|RegSetValue|RegCreateKey|AdjustTokenPrivileges|OpenProcess|MiniDumpWriteDump)"
    r"|mozilla/|user-agent|password|passwd|token|wallet|bitcoin|telegram|discord|webhook|mutex|\.onion|base64|-enc|iex\b"
    r"|[A-Za-z0-9+/]{40,}={0,2}$)")


def _floss(cid: str) -> str:
    """FLOSS per binary: every decoded / stack / tight string (with its function), and of the
    static ones those worth reading (URLs, domains, IPs, paths, registry, commands, APIs of
    injection / network / crypto, credentials, long base64). Every string: the ZIP export."""
    paths = ai_tools._paths(cid)
    out = ["# FLOSS strings (relevant)", "",
           "_Decoded, stack and tight strings whole; of the static ones, those that look like an IOC, a path, "
           "a registry key, a command, an API of interest, a credential or encoded data. Every string FLOSS "
           "found is in the ZIP export (`tool_output/floss.*.txt`)._", ""]
    n = 0
    for label, res in _module_results(paths):
        for it in res.get("items") or [] if isinstance(res.get("items"), list) else []:
            fl = it.get("floss") if isinstance(it, dict) else None
            if not isinstance(fl, dict) or not (fl.get("status") or it.get("floss_strings")):
                continue
            n += 1
            name = it.get("label") or it.get("filename") or it.get("stored_path") or label
            out += [f"## {label} › {name}", "", f"{fl.get('status')} · {_md(fl.get('detail'))}"
                    + (f" · complete output: `{fl['output_full'].rsplit('/', 1)[-1]}`" if fl.get("output_full") else ""), ""]
            full = _read_rel(paths, fl.get("output_full"))
            if full and "\n## all strings" in full:
                head, rest = full.split("\n## all strings", 1)
                allstr = rest.split("\n", 2)[-1].splitlines()
                out += [head.split("\n", 2)[-1].strip(), ""]
            else:
                allstr = [str(x) for x in it.get("floss_strings") or []]
                loc = fl.get("located") or []
                for kind in ("decoded", "stack", "tight"):
                    xs = [x.get("string") for x in loc if str(x.get("kind", "")).startswith(kind)]
                    out += [f"## {kind} strings ({len(xs)})", "", _fence("\n".join(map(str, xs))) if xs else "_(none)_\n"]
            rel = [x for x in allstr if _RELEVANT.search(x)]
            out += [f"### Relevant strings ({len(rel)} of {len(allstr)})", "", _fence("\n".join(rel)) if rel else "_(none)_\n"]
    if not n:
        out.append("_(FLOSS did not run on this case)_")
    return "\n".join(out)


_RES_KIND = {"exec": "runs it", "load": "loads it", "write": "writes it", "value": "computes it"}


def _resolution(cid: str) -> str:
    """Every script evaluated statically: stages with their recipe, downloads, calls not resolved
    and the trace — how each hidden stage was reached."""
    paths = ai_tools._paths(cid)
    out = ["# Resolution (scripts evaluated statically)", "",
           "_Each script's values and operations followed (nothing executed) to what it runs, loads or writes._", ""]
    n = 0
    for label, res in _module_results(paths):
        for sc in res.get("scripts") or [] if isinstance(res.get("scripts"), list) else []:
            r = sc.get("resolution") if isinstance(sc, dict) else None
            if not r or not (r.get("stages") or r.get("downloads") or r.get("unresolved")
                             or (r.get("sandbox") or {}).get("events")):
                continue
            n += 1
            out += [f"## {label} › {sc.get('origin') or sc.get('location') or ''}", ""]
            if r.get("stages"):
                out += ["### Stages", "", _table(["#", "Does", "Call", "Result", "Recipe", "SHA-256"], [
                    [i + 1, _RES_KIND.get(st.get("kind"), st.get("kind")) + (" (later stage)" if st.get("depth") else ""),
                     st.get("sink"), f"{st.get('type')} {st.get('size')} B", " → ".join(st.get("recipe") or []),
                     st.get("sha256")] for i, st in enumerate(r["stages"])])]
            if r.get("downloads"):
                out += ["### Downloads (not fetched)", "", _table(["Line", "URL", "Method", "Use", "Saved to"], [
                    [d.get("line"), d.get("url"), d.get("method"), d.get("use"), d.get("saved_to", "")] for d in r["downloads"]])]
            if r.get("unresolved"):
                out += ["### Dynamic calls not resolved", "",
                        "_The name or data depends on something only on the victim's machine (or the C2)._", "",
                        _table(["Line", "Expression", "Depends on", "Why"], [
                            [u.get("line"), u.get("expression"), u.get("depends_on"), u.get("why")] for u in r["unresolved"]])]
            if r.get("steps"):
                out += ["### Trace", "", _table(["Line", "Step", "Value", "Recipe"], [
                    [t.get("line"), t.get("what"), t.get("value"), " → ".join(t.get("recipe") or [])] for t in r["steps"]])]
            if r.get("errors"):
                out += ["### Statements not followed", "", _fence("\n".join(r["errors"]))]
            sbx = r.get("sandbox") or {}
            if sbx.get("events"):
                out += [f"### Seen in the sandbox ({sbx.get('tool', 'emulator')})", "",
                        "_The code ran in a hooked engine (no network, no real disk) — next to the static result._", "",
                        _table(["What", "Call", "Detail"], [[e.get("kind"), e.get("what"), e.get("detail")]
                                                            for e in sbx["events"]])]
    if not n:
        out.append("_(no script was followed to a stage, a download or a dynamic call)_")
    return "\n".join(out)


def _full_fields(obj: Any, path: str) -> list[tuple[str, str]]:
    """(where, case-relative file) of every ``*_full`` text kept whole (document text, PDF objects,
    page text…) — the tool outputs and FLOSS have their own sections."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        tool = isinstance(obj.get("output"), str) or "returncode" in obj
        for k, v in obj.items():
            ks = str(k)
            if ks.endswith("_full") and isinstance(v, str) and v.startswith("results/"):
                if not (tool and ks in ("output_full", "stderr_full")) and not v.rsplit("/", 1)[-1].startswith("floss"):
                    out.append((f"{path} › {ks[:-5]}", v))
            elif not ks.startswith("_"):
                out += _full_fields(v, f"{path} › {ks}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _full_fields(v, f"{path}[{i}]")
    return out


def _content(cid: str) -> str:
    """What a module read from a file and keeps only in part in its result (the text of a document
    or a PDF, the dictionary of every PDF object, a page's visible text…), whole."""
    paths = ai_tools._paths(cid)
    out = ["# Complete content", "",
           "_Text the tabs show in part — a document's or PDF's text, every PDF object's dictionary, "
           "a page's visible text — whole._", ""]
    seen: set[str] = set()
    for label, res in _module_results(paths):
        for where, rel in _full_fields(res, label):
            if rel in seen:
                continue
            seen.add(rel)
            text = _read_rel(paths, rel)
            if text is not None:
                out += [f"## {where}", "", f"{len(text)} characters", "", _fence(text)]
    if not seen:
        out.append("_(nothing longer than what the tabs show)_")
    return "\n".join(out)


def _email_source(data: bytes) -> list[str]:
    """One message read straight from its bytes: the header block verbatim, every text / HTML
    body whole, every link, every attachment (name, type, size, SHA-256)."""
    import email
    import email.policy
    import hashlib
    import re
    m = re.search(rb"\r?\n\r?\n", data)
    head = data[:m.start()] if m else data
    out = ["### Headers (verbatim, in order)", "", _fence(head.decode("utf-8", "replace"))]
    msg = email.message_from_bytes(data, policy=email.policy.default)
    links: list[str] = []
    atts = []
    for i, part in enumerate(msg.walk()):
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        disp = part.get_content_disposition()
        if fname or disp == "attachment" or not ctype.startswith("text/"):
            raw = part.get_payload(decode=True) or b""
            atts.append([fname or "(no name)", ctype, disp or "", len(raw), hashlib.sha256(raw).hexdigest()])
            continue
        try:
            body = part.get_content()
        except Exception:  # noqa: BLE001  (a broken charset: the bytes as UTF-8)
            body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        part_head = "\n".join(f"{k}: {v}" for k, v in part.items())
        out += [f"### Part {i}: {ctype} ({len(body)} characters)", "", _fence(part_head) if part_head else "",
                _fence(str(body), "html" if ctype == "text/html" else "")]
        if ctype == "text/html":
            links += re.findall(r"""(?i)(?:href|src|action)\s*=\s*["']?([^"'\s>]+)""", str(body))
    links = list(dict.fromkeys(links))
    out += [f"### Links in the HTML ({len(links)})", "", _fence("\n".join(links)) if links else "_(none)_\n",
            f"### Attachments ({len(atts)})", "", _table(["Name", "Type", "Disposition", "Size", "SHA-256"], atts)]
    return out


def _email(cid: str) -> str:
    """Every message of the case (the original and each attached / nested one), read from its
    own bytes: headers verbatim, bodies whole, links and attachments — what the email tabs show
    in part (the module result keeps 20,000 characters of each body)."""
    paths = ai_tools._paths(cid)
    manifest = read_json(paths.manifest) or {}
    targets: list[tuple[str, str]] = []
    if (paths.subresult("email")).is_file():
        targets.append(("the case file", (manifest.get("original") or {}).get("stored_path") or ""))
    vdir = paths.results_dir / "nested_views"
    for p in sorted(vdir.glob("*.json")) if vdir.is_dir() else []:
        v = read_json(p) or {}
        if "email" in (v.get("modules") or {}) and v.get("stored_path"):
            targets.append((f"Nested › {v.get('chain') or v.get('filename')}", v["stored_path"]))
    out = [f"# Email messages ({len(targets)})", ""]
    for label, rel in targets:
        f = (paths.root / rel) if rel else None
        out += [f"## {label}: `{Path(rel).name if rel else ''}`", ""]
        try:
            data = f.read_bytes() if f else b""
        except OSError:
            data = b""
        if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":       # Outlook .msg: its transport headers, as parsed
            em = read_json(paths.subresult("email")) or {}
            out += ["_(Outlook .msg: headers as read from its transport headers; bodies in Raw modules › email)_", "",
                    _fence("\n".join(f"{h.get('name')}: {h.get('value')}" for h in em.get("headers") or []))]
        elif data:
            out += _email_source(data)
        else:
            out.append("_(file not available)_")
    if not targets:
        out.append("_(no email in this case)_")
    return "\n".join(out)


def _code_files(cid: str) -> str:
    """The complete source of every script (original and deobfuscated) as dumped under
    extracted/code/ — the module results keep 60–80k characters of each."""
    paths = ai_tools._paths(cid)
    d = paths.extracted_dir / "code"
    files = sorted(p for p in d.rglob("*") if p.is_file()) if d.is_dir() else []
    out = [f"# Code files (complete, {len(files)})", "",
           "_Every script recovered, original and deobfuscated, whole (extracted/code/)._", ""]
    for p in files:
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            out += [f"## {p.relative_to(paths.root).as_posix()}", "", f"_(binary, {len(raw)} bytes)_", ""]
            continue
        lang = p.suffix.lstrip(".").lower()
        out += [f"## {p.relative_to(paths.root).as_posix()}", "", _fence(raw.decode("utf-8", "replace"),
                                                                         {"ps1": "powershell", "vbs": "vbnet", "bat": "bat",
                                                                          "py": "python", "js": "javascript"}.get(lang, ""))]
    if not files:
        out.append("_(no script recovered)_")
    return "\n".join(out)


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
                       [[m.get("method"), ", ".join(m.get("categories") or []), ", ".join(m.get("calls") or []),
                         " · ".join(m.get("strings") or []), " · ".join(m.get("arrays") or [])]
                        for m in (cil.get("interesting") or [])]),
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
        out += ["", "### User strings (#US)", "", _fence("\n".join(r.get("strings") or []))]
    return "\n".join(out)


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
            out += [f"| {n['name']} | {str(n['value']).replace('|', '/')} | {n['status']} | {n['extractor']} | {n['confidence']} |"
                    for n in norm]
        out += ["", _fence(json.dumps({"summary": c.get("summary"), "sections": c.get("sections"),
                                       "fields": c.get("fields")}, ensure_ascii=False,
                                      indent=1, default=str), "json")]
    for pr in c2.get("protected") or []:
        out += ["", f"- **protected** — {pr.get('object')}: "
                + ", ".join(f"{x.get('name')} ({x.get('evidence')})" for x in pr.get("protectors") or [])
                + f". {pr.get('note', '')}"]
    if not cfgs:
        out.append("_(no configuration found, or C2 not run)_")
    # every extractor's raw output, per object, of every C2 run
    base = paths.results_dir / "c2_runs"
    for run in sorted(d for d in base.iterdir() if d.is_dir()) if base.is_dir() else []:
        out += ["", f"## Extractors' raw output — run {run.name}", ""]
        for f in sorted(run.glob("*.json")):
            r = read_json(f) or {}
            out += [f"### {r.get('object') or f.stem}", "", _fence(json.dumps(r, ensure_ascii=False, indent=1, default=str), "json")]
    return "\n".join(out)


def _network(cid: str) -> str:
    return "# Network checks\n\n" + _fence(json.dumps(ai_tools.get_network_checks(cid), ensure_ascii=False,
                                                       indent=1, default=str), "json")


def _modules(cid: str) -> str:
    paths = ai_tools._paths(cid)
    out = ["# Raw module results", "",
           "_Every module's JSON result, as stored, complete. The sections above are the readable view._", ""]
    files = [p for p in sorted(paths.results_dir.rglob("*.json"))
             if not (p.parent == paths.results_dir and p.stem in ("summary", "findings"))
             and "c2_runs" not in p.parts]                            # (C2 raw: in the C2 section)
    root = getattr(paths, "root", paths.results_dir.parent)
    files += sorted((root / "code").glob("*.json")) if (root / "code").is_dir() else []
    for p in files:
        try:
            text = json.dumps(json.loads(p.read_text(encoding="utf-8")), ensure_ascii=False, indent=1, default=str)
        except (OSError, ValueError):
            continue
        name = p.stem if p.parent == paths.results_dir else p.relative_to(root).as_posix()
        out += [f"## {name}", "", _fence(text, "json")]
    return "\n".join(out)


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
            strings = "; ".join(f"{x.get('id')}@{x.get('offset')}: {str(x.get('text', ''))}"
                                for x in (m.get("strings") or []))
            rows.append([m.get("rule"), h.get("file"), meta.get("description") or meta.get("desc") or "",
                         ", ".join(m.get("tags") or []), strings])
    out += ["", _table(["rule", "object", "description", "tags", "matched strings"], rows)]
    if y.get("errors"):
        out += ["", "**Rule errors:**", ""] + [f"- {_md(e)}" for e in y["errors"]]
    return "\n".join(out)


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
             c.get("object", ""), ", ".join(f"{k}: {v}" for k, v in (c.get("fields") or {}).items())] for c in cfgs]
    out += ["", "## Products in the objects", "", _table(["product", "kind", "instance", "object", "settings"], rows)]
    ms = r.get("mentions") or []
    out += ["## Named in the text", "", _table(["product", "severity", "why", "where", "context"],
                                               [[m.get("product"), m.get("severity"), m.get("why"), m.get("location"),
                                                 str(m.get("snippet", ""))] for m in ms])]
    iocs = read_json(paths.subresult("iocs")) or {}
    tagged = [i for i in iocs.get("iocs") or [] if i.get("rmm")]
    out += ["## IOCs of a product", "", _table(["type", "value", "product", "why"],
                                               [[i["type"], i["value"], i["rmm"].get("product"), i["rmm"].get("why")]
                                                for i in tagged])]
    return "\n".join(out)


SECTIONS: list[tuple[str, str, Callable[[str], str]]] = [
    ("summary", "Summary", _summary), ("findings", "Findings", _findings), ("iocs", "IOCs", _iocs),
    ("email", "Email", _email),
    ("nested", "Nested / stages", _nested), ("decrypted", "Decrypted", _decrypted), ("code", "Code", _code),
    ("dotnet", ".NET", _dotnet), ("ml", "Machine Learning", _ml), ("yara", "YARA", _yara), ("c2", "C2", _c2),
    ("rmm", "RMM / remote access", _rmm),
    ("network", "Network checks", _network), ("resolution", "Resolution", _resolution), ("floss", "FLOSS strings", _floss),
    ("tools", "Tool outputs", _tools), ("content", "Complete content", _content),
    ("codefiles", "Code files", _code_files),
    ("modules", "Raw modules", _modules),
]


def build(case_id: str) -> list[dict[str, Any]]:
    """[{id, title, markdown, chars}] — a failing section says so instead of breaking the rest."""
    ai_tools._paths(case_id)
    out = []
    for sid, title, fn in SECTIONS:
        try:
            with ai_tools.no_limits():       # the chat's caps do not apply to the export
                md = fn(case_id)
        except Exception as exc:  # noqa: BLE001
            md = f"# {title}\n\n_(could not build this section: {exc})_\n"
        out.append({"id": sid, "title": title, "markdown": md, "chars": len(md)})
    return out


def full(case_id: str) -> str:
    head = ("<!-- DocuTraceX case export (Markdown). Static analysis results; findings are not verdicts until "
            "marked by the analyst. -->\n\n")
    return head + "\n\n---\n\n".join(s["markdown"] for s in build(case_id))
