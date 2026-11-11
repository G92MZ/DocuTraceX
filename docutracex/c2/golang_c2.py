"""Go implants: framework + C2 endpoints from the Go analysis, exported to the
C2 contract (Go ↔ C2 integration).

Works on its own and gets better with the Go module:

* **Always** (own parser, no tools): the Go version, the main module and the
  framework, from BuildInfo and the function names in pclntab (Sliver, Merlin,
  Mythic Go agents, chisel / frp tunnels…), and URLs / host:port literals in the
  read-only data (low confidence: a literal is not proof it is the C2).
* **When the Go module ran on the object** (``results/golang.json`` + its code
  analysis): the endpoints come with their provenance and a higher confidence —
  a value in a ``go:embed`` configuration or decrypted by the crypto phase
  (high), a string used by a function that calls the network (medium), Garble
  literals rebuilt by emulation — plus the network / crypto functions and
  capabilities, as fields of the configuration.

It never repeats the Go module's findings: it adds one C2 configuration (the
contract's finding), and the Go capabilities stay in the Go tab.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

FRAMEWORKS: tuple[tuple[str, str], ...] = (
    ("github.com/bishopfox/sliver", "Sliver"), ("sliverpb.", "Sliver"),
    ("github.com/Ne0nd0g/merlin", "Merlin"), ("github.com/MythicAgents/", "Mythic (Go agent)"),
    ("github.com/jpillora/chisel", "chisel (tunnel)"), ("github.com/fatedier/frp", "frp (tunnel)"),
    ("github.com/hashicorp/yamux", ""),              # multiplexing: context only, never a family on its own
)
NET_CALLEES = ("net/http.", "net.Dial", "net.(*Dialer)", "crypto/tls.Dial", "crypto/tls.(*Dialer)",
               "github.com/gorilla/websocket.", "nhooyr.io/websocket.", "golang.org/x/net/websocket.",
               "github.com/miekg/dns.", "net.Listen", "net.ResolveTCPAddr", "net.LookupTXT")
CFG_KEYS = re.compile(r"(?i)^(c2|cc|server|servers|host|hosts|url|urls|addr|address|callback|endpoint|domain|"
                      r"fallback|proxy|beacon|panel|gate)s?$")
_URL = re.compile(r"\b(?:https?|wss?)://[A-Za-z0-9.\-]+(?::\d{2,5})?(?:/[\x21-\x7e]{0,200})?")
_HOSTPORT = re.compile(r"\b(?:(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+\.[A-Za-z]{2,24}):\d{2,5}\b")
_IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
MAX_C2 = 30


def prefilter(data: bytes) -> bool:
    return b"\xff Go buildinf:" in data or b" Go build ID: " in data or b"runtime.gopanic" in data


def _case_root(path: Path) -> Path | None:
    for parent in list(path.parents)[:6]:
        if (parent / "case.json").is_file():
            return parent
    return None


def _go_context(path: Path, sha256: str) -> dict[str, Any] | None:
    """The Go module's code analysis of this object, if it ran."""
    root = _case_root(path)
    if root is None:
        return None
    try:
        g = json.loads((root / "results" / "golang.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not any(o.get("sha256") == sha256 for o in g.get("objects") or []):
        return None
    from ..codeanalysis import case as code_case
    try:
        return code_case.load(root, sha256, "go") or {}
    except Exception:  # noqa: BLE001
        return {}


def _norm(v: str) -> str:
    return v.strip().strip("'\",;").rstrip("/") if "://" not in v else v.strip().strip("'\",;")


def _endpoints(text: str) -> list[str]:
    out = [m.group(0).rstrip(".,;)'\"") for m in _URL.finditer(text)]
    out += [m.group(0) for m in _HOSTPORT.finditer(text) if not any(m.group(0) in u for u in out)]
    return out


def _config_values(obj: Any, out: list[str], depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if CFG_KEYS.match(str(k)) and isinstance(v, (str, list)):
                for x in v if isinstance(v, list) else [v]:
                    if isinstance(x, str) and x.strip():
                        out.append(x.strip())
            else:
                _config_values(v, out, depth + 1)
    elif isinstance(obj, list):
        for x in obj:
            _config_values(x, out, depth + 1)


def _plausible(v: str) -> bool:
    if "://" in v:
        host = v.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    else:
        host = v.rsplit(":", 1)[0] if ":" in v else v
    if not host or "." not in host:
        return False
    if _IP.match(host):
        return all(0 <= int(x) <= 255 for x in host.split("."))
    return not host.endswith((".go", ".s", ".c", ".h")) and not host.startswith(("golang.org", "go.dev", "github.com"))


def extract(path: Path, data: bytes) -> list[dict[str, Any]]:
    import hashlib

    from ..golang import detect
    ident = detect.identify(data)
    if ident.get("state") not in ("Confirmed", "Likely"):
        return []
    from ..codeanalysis import case as code_case
    names = [f["name"] for f in code_case.go_names(data, ident)]
    if not names and ident.get("_pcln"):              # names without ranges are enough to name a framework
        try:
            names = detect._func_names(data, ident["_pcln"])
        except Exception:  # noqa: BLE001
            names = []
    bi = ident.get("buildinfo") or {}
    deps = [d.get("path", "") for d in bi.get("deps") or []]
    framework, why = "", []
    for needle, fam in FRAMEWORKS:
        hit = next((m for m in deps if m.startswith(needle)), "") or next((n for n in names if needle in n), "")
        if hit and fam:
            framework = framework or fam
            if f"{fam}: {hit}" not in why:
                why.append(f"{fam}: {hit}")
    sha = hashlib.sha256(data).hexdigest()
    ctx = _go_context(path, sha)
    found: dict[str, dict[str, Any]] = {}             # endpoint → {source, confidence}
    rank = {"high": 3, "medium": 2, "low": 1}

    def add(v: str, source: str, conf: str) -> None:
        v = _norm(v)
        if not v or not _plausible(v) or len(found) >= MAX_C2 and v not in found:
            return
        cur = found.get(v)
        if cur is None or rank[conf] > rank[cur["confidence"]]:
            found[v] = {"source": source, "confidence": conf}
    net_fns: list[str] = []
    crypto: list[str] = []
    if ctx:
        for fs in (ctx.get("resources") or {}).get("embed") or []:
            for f in fs.get("files") or []:
                p = (_case_root(path) or Path("/nonexistent")) / (f.get("stored_path") or "-")
                if f.get("kind") == "configuration" and p.is_file():
                    try:
                        body = p.read_bytes()[:1024 * 1024].decode("utf-8", "replace")
                        vals: list[str] = []
                        try:
                            _config_values(json.loads(body), vals)
                        except ValueError:
                            vals = _endpoints(body)
                        for v in vals:
                            for e in _endpoints(v) or ([v] if _plausible(_norm(v)) else []):
                                add(e, f"go:embed {f['name']}", "high")
                    except OSError:
                        pass
        for pt in (ctx.get("crypto") or {}).get("plaintexts") or []:
            for e in _endpoints(pt.get("text") or ""):
                add(e, f"decrypted ({pt.get('method')}) in {pt.get('function')}", "high")
        for fn in ctx.get("functions") or []:
            callees = fn.get("callee_names") or []
            talks = [c for c in callees if c.startswith(NET_CALLEES)]
            if talks:
                net_fns.append(f"{fn['name']} → {', '.join(sorted(set(talks))[:3])}")
            for s in (fn.get("strings") or []) + (fn.get("floss") or []):
                for e in _endpoints(s.get("value") or ""):
                    add(e, f"string in {fn['name']}" + (" (calls the network)" if talks else ""),
                        "medium" if talks else "low")
        for g in (ctx.get("garble") or {}).get("strings") or []:
            for e in _endpoints(g.get("value") or ""):
                add(e, f"Garble literal (emulated) in {g.get('function')}", "medium")
        crypto = [a.get("name") or a.get("algorithm") or "" for a in (ctx.get("crypto") or {}).get("algorithms") or []]
    else:                                              # without the Go module: literals in the read-only data
        text = data.decode("latin-1")
        for e in _endpoints(text)[:200]:
            add(e, "literal in the binary (Go module not run)", "low")
    # a bare literal is not a C2: without a framework, only endpoints with a real link
    # (go:embed configuration, decrypted, used by a function that calls the network)
    if not framework and not any(rank[x["confidence"]] >= 2 for x in found.values()):
        return []
    c2 = sorted(found, key=lambda v: (-rank[found[v]["confidence"]], v))[:MAX_C2]
    best = found[c2[0]]["confidence"] if c2 else "low"
    conf = "high" if best == "high" or (framework and c2) else ("medium" if best == "medium" else "low")
    summary: dict[str, Any] = {}
    if c2:
        summary["C2"] = c2
        summary["Where from"] = [f"{v} — {found[v]['source']} ({found[v]['confidence']})" for v in c2[:10]]
    summary["Go version"] = ident.get("go_version") or ""
    if bi.get("path"):
        summary["Module"] = bi["path"]
    if framework:
        summary["Framework"] = framework
    if net_fns:
        summary["Network functions"] = net_fns[:10]
    if crypto:
        summary["Crypto"] = sorted({c for c in crypto if c})[:10]
    fields = {"go_version": ident.get("go_version") or "", "module": bi.get("path") or "",
              "framework": framework, "framework_evidence": why[:10],
              "endpoints": [{"value": v, **found[v]} for v in c2],
              "go_analysis": "used" if ctx else "not run on this object (own parser only)"}
    return [{"family": framework if framework and "tunnel" not in framework else "Go implant",
             "kind": "configuration" if c2 else "indicators", "c2": c2, "confidence": conf,
             "method": "Go analysis (BuildInfo, pclntab" + (", code strings per function, go:embed, crypto" if ctx else "")
                       + ")", "fields": fields, "summary": summary,
             "indicators": why[:10] if not c2 else []}]
