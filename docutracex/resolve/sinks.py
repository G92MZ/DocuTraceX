"""What a script hands to the calls that matter: the stages that go to Nested.

An evaluator reports here every value that reaches

- an **execute** call (``IEX``, ``ScriptBlock::Create``, ``eval``, ``exec``, ``Execute``,
  ``Function``…): the code is the next stage, resolved again on its own;
- a **load** call (``Assembly.Load``, ``VirtualAlloc`` + copy, ``ctypes``…): the bytes are a
  binary stage (PE, .NET, shellcode);
- a **write** call (``WriteAllBytes``, ``open().write``, ``fwrite``, ``> file``): the file the
  script would drop;
- a **download** (``DownloadString``, ``Invoke-WebRequest``, ``urlopen``…): not fetched — the URL,
  the method and what the script would do with it, for the analyst to get it;
- a call it could **not resolve** (a name, key or data that only exists on the victim's
  machine): the expression, what it depends on and why.

:meth:`Sinks.decoded_stages` gives them in the shape every language engine already returns
(``scripts[i]["decoded_stages"]``), which ``decrypted.payloads_from`` turns into Nested children.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import Any

from . import transforms
from .value import Value

MAX_STAGES = 64
_SCRIPT_EXT = {".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".psm1", ".bat", ".cmd", ".py", ".pl",
               ".php", ".rb", ".lua", ".sh", ".html", ".htm", ".svg", ".au3", ".ahk", ".tcl"}
MAX_TEXT = 8 * 1024 * 1024


@dataclass
class Stage:
    kind: str                     # exec | load | write
    sink: str                     # the call it reached (IEX, Assembly.Load, WriteAllBytes…)
    data: bytes | str
    recipe: tuple[str, ...]
    target: str = ""              # write: the path; load: the entry point
    line: int | None = None
    depth: int = 0                # 0: computed by the script itself; >0: by code it runs (a later stage)
    ext: str = ""                 # the stage's language when not the script's (a PowerShell -enc in Python)

    @property
    def sha256(self) -> str:
        b = self.data if isinstance(self.data, bytes) else self.data.encode("utf-8", "replace")
        return hashlib.sha256(b).hexdigest()


@dataclass
class Sinks:
    lang: str
    stages: list[Stage] = field(default_factory=list)
    downloads: list[dict[str, Any]] = field(default_factory=list)
    unresolved: list[dict[str, Any]] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)       # the Resolution tab's trace
    depth: int = 0                # set by the evaluator while it runs code the script hands to "execute"
    _seen: set[str] = field(default_factory=set)

    # -- reports from the evaluators --------------------------------------------------
    def _add(self, st: Stage) -> None:
        if len(self.stages) >= MAX_STAGES or st.sha256 in self._seen:
            return
        self._seen.add(st.sha256)
        st.depth = self.depth
        self.stages.append(st)

    def _downloaded(self, v: Value, what: str) -> bool:
        """An unknown value that is downloaded content: the download says what is done with it."""
        if v.known or not v.why.startswith("the content downloaded from "):
            return False
        url = v.why[len("the content downloaded from "):]
        for d in self.downloads:
            if d["url"] == url and what not in d["use"]:
                d["use"] = f"{d['use']}, then {what}" if d["use"] != "returns it to the script" else what
        return True

    def exec_(self, code: Value, sink: str, line: int | None = None) -> None:
        if self._downloaded(code, f"runs it as code ({sink})"):
            return
        if not code.known:
            self.unresolved_(f"{sink}(…)", code.why, f"the code {sink} runs is computed from "
                             f"something not in the script", line)
            return
        text = code.as_str() if code.kind != "bytes" else transforms.as_text(code.v)
        if text and text.strip():
            self._add(Stage("exec", sink, text[:MAX_TEXT], code.recipe + (sink,), line=line))

    def load(self, data: Value, sink: str, target: str = "", line: int | None = None) -> None:
        if self._downloaded(data, f"loads it ({sink})"):
            return
        if not data.known:
            self.unresolved_(f"{sink}(…)", data.why, "the bytes it loads are computed from something "
                             "not in the script", line)
            return
        raw = data.as_bytes()
        if raw:
            self._add(Stage("load", sink, raw, data.recipe + (sink,), target, line))

    def value_(self, text: Value, what: str, line: int | None = None) -> None:
        """Text the script decoded and kept (a configuration with its C2): mined for IOCs as a stage."""
        t = text.as_str() if text.known else None
        if t and t.strip():
            self._add(Stage("value", what, t[:MAX_TEXT], text.recipe + (what,), line=line))

    def write(self, data: Value, path: str, sink: str, line: int | None = None) -> None:
        if not data.known:
            return
        raw = data.v if data.kind == "bytes" else (data.as_str() or "").encode("utf-8", "replace")
        if raw:
            self._add(Stage("write", sink, raw, data.recipe + (f"{sink} {path}",), path, line))

    def download(self, url: Value, method: str, use: str, line: int | None = None,
                 dest: str = "", then: tuple[str, ...] = ()) -> None:
        """A download: ``use`` = what the script does with it (``executes it as code``, ``loads it
        as an assembly``, ``saves it to <dest> and runs it``…), ``then`` = the transformations
        it applies to it (``base64``, ``xor(key …)``…)."""
        u = url.as_str() if url.known else None
        rec = {"url": u or f"<{url.why or 'computed'}>", "method": method, "use": use, "line": line,
               "resolved": bool(u), "recipe": list(url.recipe)}
        if dest:
            rec["saved_to"] = dest
        if then:
            rec["then"] = list(then)
        if rec not in self.downloads:
            self.downloads.append(rec)

    def unresolved_(self, expr: str, depends: str, why: str, line: int | None = None) -> None:
        rec = {"expression": expr[:400], "depends_on": depends or "unknown", "why": why, "line": line}
        if rec not in self.unresolved and len(self.unresolved) < 200:
            self.unresolved.append(rec)

    def step(self, line: int | None, what: str, value: Value) -> None:
        if len(self.steps) < 2000:
            self.steps.append({"line": line, "what": what[:200], "value": value.short(120),
                               "recipe": list(value.recipe)[-6:]})

    # -- out ------------------------------------------------------------------------------
    def decoded_stages(self) -> list[dict[str, Any]]:
        """The stages as the engines' ``decoded_stages`` (text or ``data_b64``)."""
        out = []
        # only what the script itself computes: what a later stage computes comes out when that
        # stage (a child in Nested) is analysed, under it
        for st in (s for s in self.stages if s.depth == 0):
            recipe = [r for r in st.recipe if r]
            if st.kind == "write" and not st.ext:
                # a file the script writes: the type its own name gives it (inv_sync.vbs, x.ps1…)
                tail = st.target.replace("/", "\\").rsplit("\\", 1)[-1]
                ext = "." + tail.rsplit(".", 1)[-1].lower() if "." in tail else ""
                st.ext = ext if ext in _SCRIPT_EXT else ""     # .tmp, .dat…: by its content
            if isinstance(st.data, str):
                out.append({"recipe": recipe, "text": st.data, "sink": st.sink, "resolved": True,
                            **({"ext": st.ext} if st.kind in ("value", "write") or st.ext else {})})
                continue
            raw = st.data
            text = None
            if transforms.magic(raw) is None and transforms.is_text(raw):
                text = transforms.as_text(raw, "utf-16-le" if raw[1:2] == b"\x00" else "utf-8")
            if text is not None and st.kind in ("exec", "write"):
                out.append({"recipe": recipe, "text": text, "sink": st.sink, "resolved": True,
                            **({"ext": st.ext} if st.kind == "write" or st.ext else {})})
            else:
                out.append({"recipe": recipe, "data_b64": base64.b64encode(raw).decode("ascii"),
                            "sink": st.sink, "resolved": True, **({"target": st.target} if st.target else {})})
        return out

    def findings(self, loc: str) -> list[dict[str, Any]]:
        """Findings for the downloads and the calls not resolved (with a short explanation)."""
        out = []
        for d in self.downloads[:50]:
            detail = (f"downloads {d['url']} ({d['method']}) and {d['use']}"
                      + (f"; saved to {d['saved_to']}" if d.get("saved_to") else "")
                      + (f"; then {' → '.join(d['then'])}" if d.get("then") else ""))
            out.append({"rule": f"{self.lang}_resolved_download", "severity": "high", "attack": "T1105",
                        "detail": detail, "location": loc,
                        "evidence": f"line {d.get('line')}: not fetched — get it and analyse it as a new case "
                                    f"(or add it to this one); recipe of the URL: {' → '.join(d['recipe']) or 'literal'}"})
        for u in self.unresolved[:50]:
            out.append({"rule": f"{self.lang}_unresolved_dynamic_call", "severity": "medium", "attack": "T1027",
                        "detail": f"dynamic call not resolved: {u['expression']}",
                        "location": loc,
                        "evidence": (f"line {u.get('line')}: it depends on {u['depends_on']} — {u['why']}. "
                                     "Its name / data is computed at run time from something that exists only on "
                                     "the victim's machine (or the C2), so it cannot be worked out from the script; "
                                     "the rest of the script was resolved.")})
        return out
