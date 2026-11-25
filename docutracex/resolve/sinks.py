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
MAX_TEXT = 8 * 1024 * 1024


@dataclass
class Stage:
    kind: str                     # exec | load | write
    sink: str                     # the call it reached (IEX, Assembly.Load, WriteAllBytes…)
    data: bytes | str
    recipe: tuple[str, ...]
    target: str = ""              # write: the path; load: the entry point
    line: int | None = None

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
    _seen: set[str] = field(default_factory=set)

    # -- reports from the evaluators --------------------------------------------------
    def _add(self, st: Stage) -> None:
        if len(self.stages) >= MAX_STAGES or st.sha256 in self._seen:
            return
        self._seen.add(st.sha256)
        self.stages.append(st)

    def exec_(self, code: Value, sink: str, line: int | None = None) -> None:
        if not code.known:
            self.unresolved_(f"{sink}(…)", code.why, f"the code {sink} runs is computed from "
                             f"something not in the script", line)
            return
        text = code.as_str() if code.kind != "bytes" else transforms.as_text(code.v)
        if text and text.strip():
            self._add(Stage("exec", sink, text[:MAX_TEXT], code.recipe + (f"→ {sink}",), line=line))

    def load(self, data: Value, sink: str, target: str = "", line: int | None = None) -> None:
        if not data.known:
            self.unresolved_(f"{sink}(…)", data.why, "the bytes it loads are computed from something "
                             "not in the script", line)
            return
        raw = data.as_bytes()
        if raw:
            self._add(Stage("load", sink, raw, data.recipe + (f"→ {sink}",), target, line))

    def write(self, data: Value, path: str, sink: str, line: int | None = None) -> None:
        if not data.known:
            return
        raw = data.v if data.kind == "bytes" else (data.as_str() or "").encode("utf-8", "replace")
        if raw:
            self._add(Stage("write", sink, raw, data.recipe + (f"→ {sink} {path}",), path, line))

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
        for st in self.stages:
            recipe = [r for r in st.recipe if r]
            if isinstance(st.data, str):
                out.append({"recipe": recipe, "text": st.data, "sink": st.sink, "resolved": True})
                continue
            raw = st.data
            text = None
            if transforms.magic(raw) is None and transforms.is_text(raw):
                text = transforms.as_text(raw, "utf-16-le" if raw[1:2] == b"\x00" else "utf-8")
            if text is not None and st.kind == "exec":
                out.append({"recipe": recipe, "text": text, "sink": st.sink, "resolved": True})
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
