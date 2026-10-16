"""AI assistant over the cases (OpenAI-compatible function calling).

Ask in natural language ("is this email phishing? what would the macro do?")
and the model answers with real data, calling DocuTraceX's read-only tools
(see ``ai_tools``): case summary, findings with marks, IOCs, module results,
network checks, search.

Works with any endpoint compatible with the OpenAI API (``/chat/completions``
+ ``tools``):

- **AI (API)**: your company's LiteLLM proxy, or a provider's API
  (base_url + api_key [+ user / extra headers your LiteLLM needs]).
- **AI (local)**: an app on your own machine exposing that API — Ollama
  (``http://localhost:11434/v1``), LM Studio (``http://localhost:1234/v1``),
  llama.cpp server… — so the data never leaves the machine.

Nothing is stored or sent on its own: the endpoint is only called when the
analyst asks a question. The tools cannot modify anything. The network-check
proxy is NOT used here (it is for contacting attacker infrastructure).
"""

from __future__ import annotations

import json
from typing import Any

from . import ai_tools

MAX_ITERS = 8
TIMEOUT = 180
MAX_TOOL_CHARS = 24000

SYSTEM_PROMPT = (
    "You are a DFIR analyst assistant inside DocuTraceX, a static forensic analyser of Office, PDF, RTF and "
    "email files. Answer using the tools, which read the analysis results of the cases (findings with the "
    "analyst's marks, IOCs, module outputs such as olevba/ViperMonkey/pdf/email/rtf, and network checks). "
    "Never invent results: if the data does not support something, say so. Cite concrete evidence (rule, "
    "tool, location, IOC, values). Explain what a technique means and its risk when useful. "
    "Answer in the language the analyst writes in. {case_hint}"
)


def _headers(cfg: dict[str, Any]) -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    key = (cfg.get("api_key") or "").strip()
    if key:
        h["Authorization"] = f"Bearer {key}"
    extra = cfg.get("extra_headers")
    if isinstance(extra, dict):
        for k, v in extra.items():
            if k and v is not None:
                h[str(k)] = str(v)
    return h


def chat(message: str, cfg: dict[str, Any], history: list[dict[str, Any]] | None = None,
         case_id: str | None = None) -> dict[str, Any]:
    """One conversation turn with the tool loop. Returns {reply, tool_trace, model}."""
    import requests

    base = (cfg.get("base_url") or "").rstrip("/")
    if not base:
        raise ValueError("base_url of the AI endpoint is missing")
    model = cfg.get("model") or ""
    if not model:
        raise ValueError("model name is missing")
    if not (message or "").strip():
        raise ValueError("empty question")
    url = base + "/chat/completions"
    hint = (f"The analyst is looking at case {case_id}; use it unless they name another one."
            if case_id else "Use list_cases to find the case the analyst means.")
    messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT.format(case_hint=hint)}]
    for h in (history or [])[-10:]:
        if h.get("role") in ("user", "assistant") and isinstance(h.get("content"), str):
            messages.append({"role": h["role"], "content": h["content"][:8000]})
    messages.append({"role": "user", "content": message})

    trace: list[dict[str, Any]] = []
    with requests.Session() as s:
        for _ in range(MAX_ITERS):
            payload: dict[str, Any] = {"model": model, "messages": messages, "tools": ai_tools.SCHEMAS,
                                       "tool_choice": "auto", "temperature": cfg.get("temperature", 0)}
            if cfg.get("user"):
                payload["user"] = cfg["user"]
            r = s.post(url, headers=_headers(cfg), json=payload, timeout=TIMEOUT)
            if r.status_code >= 400:
                raise RuntimeError(f"HTTP {r.status_code}: {r.text[:500]}")
            data = r.json()
            msg = ((data.get("choices") or [{}])[0]).get("message") or {}
            calls = msg.get("tool_calls") or []
            if not calls:
                return {"reply": msg.get("content") or "", "tool_trace": trace, "model": data.get("model", model)}
            messages.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
            for tc in calls:
                fn = tc.get("function") or {}
                name = fn.get("name", "")
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                if case_id and "case_id" not in args and name not in ("list_cases",):
                    args["case_id"] = case_id
                result = ai_tools.run_tool(name, args)
                text = json.dumps(result, ensure_ascii=False, default=str)
                trace.append({"tool": name, "args": args, "error": result.get("error"), "chars": len(text)})
                messages.append({"role": "tool", "tool_call_id": tc.get("id", ""), "name": name,
                                 "content": text[:MAX_TOOL_CHARS]})
    return {"reply": "(Reached the limit of tool steps without a final answer. Try rephrasing the question.)",
            "tool_trace": trace, "model": model}
