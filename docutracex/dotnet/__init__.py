""".NET analysis (phase 1: identification and metadata).

Every .NET assembly of the case (the original and every nested object,
unpacked / extracted / dropped) is read with ``dnfile`` (MIT, pure Python):
runtime and assembly identity, referenced assemblies, types and methods,
P/Invoke imports (the native APIs the managed code calls), the framework
APIs it references (WebClient, Process.Start, Assembly.Load…), resources,
the user strings (#US) and obfuscator / packer traits. Static only: the
assembly is parsed, never loaded or run.
"""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

log = get_logger(__name__)

MAX_SIZE = 128 * 1024 * 1024
MAX_STRINGS = 5000
MAX_TYPES = 3000

# framework APIs worth pointing out: (TypeRef namespace.name or member, category, label)
APIS: list[tuple[str, str, str]] = [
    ("System.Net.WebClient", "network", "web client"), ("System.Net.Http.HttpClient", "network", "HTTP client"),
    ("System.Net.HttpWebRequest", "network", "HTTP request"), ("System.Net.Sockets.TcpClient", "network", "TCP client"),
    ("System.Net.Sockets.Socket", "network", "socket"), ("System.Net.Mail.SmtpClient", "network", "SMTP (exfiltration?)"),
    ("System.Net.FtpWebRequest", "network", "FTP (exfiltration?)"), ("System.Net.Dns", "network", "DNS"),
    ("System.Diagnostics.Process", "exec", "process start / enumeration"),
    ("System.Reflection.Assembly", "process", "Assembly.Load / reflection (in-memory payload?)"),
    ("System.Reflection.MethodBase", "process", "reflection invoke"),
    ("System.Runtime.InteropServices.Marshal", "process", "unmanaged memory (shellcode?)"),
    ("Microsoft.Win32.Registry", "persistence", "registry"), ("Microsoft.Win32.RegistryKey", "persistence", "registry"),
    ("System.Security.Cryptography", "crypto", "cryptography"), ("System.IO.Compression", "transform", "compression"),
    ("System.Convert", "transform", "Base64 conversion"), ("System.Management", "recon", "WMI queries"),
    ("System.Windows.Forms.Clipboard", "recon", "clipboard"), ("System.Drawing.Graphics", "recon", "screen capture (CopyFromScreen?)"),
    ("System.Environment", "recon", "environment / user / machine"), ("System.IO.File", "files", "file access"),
    ("System.IO.Directory", "files", "directory enumeration"), ("System.Threading.Mutex", "recon", "mutex (single instance)"),
]
OBFUSCATORS: list[tuple[str, re.Pattern]] = [
    ("ConfuserEx", re.compile(r"ConfusedByAttribute|ConfuserEx", re.IGNORECASE)),
    ("SmartAssembly", re.compile(r"SmartAssembly\.|PoweredByAttribute", re.IGNORECASE)),
    ("Dotfuscator", re.compile(r"DotfuscatorAttribute|PreEmptive", re.IGNORECASE)),
    ("Babel .NET", re.compile(r"BabelObfuscatorAttribute|BabelAttribute", re.IGNORECASE)),
    ("Eazfuscator.NET", re.compile(r"Eazfuscator", re.IGNORECASE)),
    ("Agile.NET / CliSecure", re.compile(r"AgileDotNetRT|CliSecureRt|ObfuscatedByAgile", re.IGNORECASE)),
    ("Crypto Obfuscator", re.compile(r"CryptoObfuscator", re.IGNORECASE)),
    (".NET Reactor", re.compile(r"\.NET Reactor|__\.NET Reactor|Eziriz", re.IGNORECASE)),
    ("KoiVM", re.compile(r"KoiVM|\bKoi\b", re.IGNORECASE)),
    ("Costura.Fody (embedded assemblies)", re.compile(r"Costura\.AssemblyLoader|^costura\.", re.IGNORECASE)),
    ("ILMerge / ILRepack", re.compile(r"ILRepack|ILMerge", re.IGNORECASE)),
]
INJECTION = {"virtualalloc", "virtualallocex", "virtualprotect", "writeprocessmemory", "createremotethread",
             "createthread", "ntcreatethreadex", "queueuserapc", "rtlmovememory", "ntunmapviewofsection",
             "setthreadcontext", "resumethread", "openprocess"}


def available() -> bool:
    import importlib.util
    return importlib.util.find_spec("dnfile") is not None


def _s(x: Any) -> str:
    v = getattr(x, "value", x)
    if isinstance(v, bytes):
        v = v.decode("utf-8", "replace")
    return str(v) if v is not None else ""


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    return round(-sum(n / len(b) * math.log2(n / len(b)) for n in c if n), 2)


def _odd(name: str) -> bool:
    """Renamed by an obfuscator: invisible / non-ASCII characters or random junk."""
    return bool(name) and any(ord(c) > 0x7E or ord(c) < 0x20 for c in name)


def parse(data: bytes) -> dict[str, Any]:
    import dnfile
    pe = dnfile.dnPE(data=data)
    try:
        n = pe.net
        if n is None or n.mdtables is None:
            return {"error": "no CLR metadata"}
        t = n.mdtables
        out: dict[str, Any] = {"runtime": _s(n.metadata.struct.Version).rstrip("\x00") if n.metadata else "",
                               "flags": [], "references": [], "types": [], "pinvoke": [], "apis": [],
                               "resources": [], "strings": [], "obfuscators": [], "traits": []}
        fl = n.struct.Flags if n.struct else 0
        flags = int(getattr(fl, "value", fl) or 0) if not hasattr(fl, "CLR_ILONLY") else 0
        if hasattr(fl, "CLR_ILONLY"):
            out["flags"] = [k for k in ("CLR_ILONLY", "CLR_32BITREQUIRED", "CLR_STRONGNAMESIGNED", "CLR_32BITPREFERRED")
                            if getattr(fl, k, False)]
        elif flags:
            out["flags"] = [k for k, v in (("CLR_ILONLY", 1), ("CLR_32BITREQUIRED", 2), ("CLR_STRONGNAMESIGNED", 8),
                                           ("CLR_32BITPREFERRED", 0x20000)) if flags & v]
        if t.Assembly and t.Assembly.num_rows:
            a = t.Assembly[0]
            out["assembly"] = {"name": _s(a.Name), "version": f"{a.MajorVersion}.{a.MinorVersion}.{a.BuildNumber}.{a.RevisionNumber}",
                               "culture": _s(a.Culture)}
        if t.Module and t.Module.num_rows:
            out["module"] = _s(t.Module[0].Name)
        for r in t.AssemblyRef or []:
            out["references"].append({"name": _s(r.Name), "version": f"{r.MajorVersion}.{r.MinorVersion}.{r.BuildNumber}.{r.RevisionNumber}"})
        # types and methods
        pin = {}
        for im in t.ImplMap or []:
            try:
                meth = im.MemberForwarded.row
                pin[_s(meth.Name)] = (_s(im.ImportScope.row.Name), _s(im.ImportName))
            except AttributeError:
                continue
        odd = total = 0
        entry_tok = int(getattr(n.struct, "EntryPointTokenOrRva", 0) or 0)
        for ti, td in enumerate(t.TypeDef or []):
            name, ns = _s(td.TypeName), _s(td.TypeNamespace)
            methods = []
            for mref in td.MethodList or []:
                m = mref.row
                mn = _s(m.Name)
                total += 1
                odd += _odd(mn)
                rec = {"name": mn, "rva": int(m.Rva or 0)}
                if mn in pin and not m.Rva:
                    rec["pinvoke"] = {"dll": pin[mn][0], "entry": pin[mn][1]}
                methods.append(rec)
            total += 1
            odd += _odd(name)
            if ti < MAX_TYPES:
                out["types"].append({"namespace": ns, "name": name, "methods": methods[:500]})
        if entry_tok and (entry_tok >> 24) == 0x06:
            idx = entry_tok & 0xFFFFFF
            k = 0
            for ty in out["types"]:
                for m in ty["methods"]:
                    k += 1
                    if k == idx:
                        out["entry_point"] = f"{ty['namespace'] + '.' if ty['namespace'] else ''}{ty['name']}::{m['name']}"
        for meth, (dll, ep) in pin.items():
            low = (ep or meth).lower()
            from ..codeanalysis.priority import CATEGORIES
            cats = [k for k, c in CATEGORIES.items() if any(x in low for x in c.get("api", ()))]
            out["pinvoke"].append({"method": meth, "dll": dll, "entry": ep or meth, "categories": cats,
                                   "injection": low.rstrip("aw") in INJECTION or low in INJECTION})
        # referenced framework types / members
        refs = set()
        for tr in t.TypeRef or []:
            refs.add(f"{_s(tr.TypeNamespace)}.{_s(tr.TypeName)}".strip("."))
        members = {}
        for mr in t.MemberRef or []:
            try:
                cls = mr.Class.row
                full = f"{_s(cls.TypeNamespace)}.{_s(cls.TypeName)}".strip(".")
                members.setdefault(full, set()).add(_s(mr.Name))
            except AttributeError:
                continue
        for full in sorted(refs):
            for pre, cat, label in APIS:
                if full == pre or full.startswith(pre + ".") or (pre.endswith("Cryptography") and full.startswith(pre)):
                    out["apis"].append({"type": full, "category": cat, "label": label,
                                        "members": sorted(members.get(full, set()))[:20]})
                    break
        out["typerefs"] = sorted(refs)[:2000]
        # resources
        res_rva = int(getattr(n.struct, "ResourcesRva", 0) or 0)
        offsets = {_s(m.Name): int(m.Offset or 0) for m in (t.ManifestResource or []) if not m.Implementation}
        for r in n.resources or []:
            raw = r.data if isinstance(r.data, (bytes, bytearray)) else b""
            if not raw and res_rva and _s(r.name) in offsets:   # dnfile parsed a .resources: take the raw bytes
                try:
                    at = res_rva + offsets[_s(r.name)]
                    ln = int.from_bytes(pe.get_data(at, 4), "little")
                    raw = bytes(pe.get_data(at + 4, ln)) if 0 < ln <= MAX_SIZE else b""
                except Exception:  # noqa: BLE001
                    raw = b""
            out["resources"].append({"name": _s(r.name), "size": len(raw), "public": bool(getattr(r, "public", True)),
                                     "entropy": _entropy(raw[:1 << 20]), "sha256": hashlib.sha256(raw).hexdigest() if raw else "",
                                     "head": raw[:8].hex(), "_data": bytes(raw)})
        # user strings
        us = n.user_strings
        if us is not None:
            off, size = 1, len(us.__data__) if hasattr(us, "__data__") else 0
            while off < size and len(out["strings"]) < MAX_STRINGS:
                try:
                    item = us.get(off)
                except Exception:  # noqa: BLE001
                    break
                if item is None or not getattr(item, "raw_size", 0):
                    break
                v = _s(item)
                if v:
                    out["strings"].append(v[:2000])
                off += item.raw_size
        # obfuscators / packers
        hay = "\n".join(list(refs) + [f"{t['namespace']}.{t['name']}" for t in out["types"]]
                        + [r["name"] for r in out["resources"]] + out["strings"][:2000] + [out.get("module", "")])
        for name, rx in OBFUSCATORS:
            m = rx.search(hay)
            if m:
                out["obfuscators"].append({"name": name, "evidence": m.group(0)[:80]})
        if total and odd / total > 0.3:
            out["traits"].append(f"{round(100 * odd / total)}% of type / method names are unreadable (renamed by an obfuscator)")
        if any(r["entropy"] > 7.5 and r["size"] > 4096 for r in out["resources"]):
            out["traits"].append("high-entropy resource(s): encrypted / compressed payload?")
        try:
            from .cil import disassemble
            c = disassemble(pe)
            out["_cil_strings"] = c.pop("_strings")
            meths = c.pop("_methods")
            try:
                from .strdec import decrypt
                c["decrypted"] = decrypt(meths)
            except Exception as exc:  # noqa: BLE001
                c["decrypted_error"] = f"string decryption: {exc}"[:200]
            out["cil"] = c
        except Exception as exc:  # noqa: BLE001  (CIL is best effort)
            out["cil"] = {"error": f"CIL disassembly: {exc}"[:200]}
        out["counts"] = {"types": len(t.TypeDef or []), "methods": total - len(t.TypeDef or []),
                         "pinvoke": len(out["pinvoke"]), "resources": len(out["resources"]), "strings": len(out["strings"])}
        return out
    finally:
        pe.close()


def _findings(item: dict[str, Any]) -> list[dict[str, Any]]:
    r = item.get("result") or {}
    loc = item["label"]
    out = [{"rule": "dotnet:identified", "severity": "info", "tool": "dotnet", "location": loc,
            "detail": f".NET assembly {((r.get('assembly') or {}).get('name') or r.get('module') or '')} "
                      f"(runtime {r.get('runtime', '?')}, {r.get('counts', {}).get('types', 0)} types)", "evidence": ""}]
    for o in r.get("obfuscators") or []:
        out.append({"rule": "dotnet:obfuscator", "severity": "medium", "tool": "dotnet", "location": loc,
                    "detail": f"obfuscator / packer: {o['name']}", "evidence": o["evidence"], "attack": "T1027"})
    inj = [p for p in r.get("pinvoke") or [] if p["injection"]]
    if len({p["entry"].lower() for p in inj}) >= 2:
        out.append({"rule": "dotnet:pinvoke_injection", "severity": "high", "tool": "dotnet", "location": loc,
                    "detail": "P/Invoke of memory / thread APIs used for shellcode loading or injection (T1055)",
                    "evidence": ", ".join(f"{p['dll']}!{p['entry']}" for p in inj[:8]), "attack": "T1055"})
    if any(a["type"] == "System.Reflection.Assembly" and ({"Load", "LoadFile", "LoadFrom"} & set(a["members"]))
           for a in r.get("apis") or []):
        out.append({"rule": "dotnet:assembly_load", "severity": "medium", "tool": "dotnet", "location": loc,
                    "detail": "loads an assembly at run time (Assembly.Load: in-memory payload?) (T1620)",
                    "evidence": "System.Reflection.Assembly.Load", "attack": "T1620"})
    cil = r.get("cil") or {}
    loaders = [m for m in cil.get("interesting") or [] if "loader" in m["categories"]
               and any(c.startswith("System.Reflection.Assembly::Load") for c in m["calls"])]
    for o in out:
        if o["rule"] == "dotnet:assembly_load" and loaders:
            o["evidence"] = "; ".join(f"{m['method']} → {', '.join(c for c in m['calls'] if '::Load' in c)}"
                                      for m in loaders[:4])
    dec = cil.get("decrypted") or []
    if dec:
        out.append({"rule": "dotnet:strings_decrypted", "severity": "medium", "tool": "dotnet", "location": loc,
                    "detail": f"{len(dec)} encrypted string(s) decrypted statically "
                              f"({', '.join(sorted({d['decryptor'] for d in dec})[:3])})",
                    "evidence": "; ".join(f"{d['output'][:60]} ({d['how']})" for d in dec[:5]), "attack": "T1140"})
    for x in r.get("resources") or []:
        for e in x.get("entries") or []:
            if e.get("pe"):
                out.append({"rule": "dotnet:resource_pe", "severity": "high", "tool": "dotnet", "location": loc,
                            "detail": f"PE embedded in managed resource {x['name']} › {e['name']} ({e['type']})",
                            "evidence": f"{e['size']} bytes", "attack": "T1027.009"})
    return out


RES_DIR = "dotnet_resources"
MIN_RESOURCE = 16
MAX_CHILDREN = 60


def _resource_child(root: Path, sha: str, label: str, x: dict[str, Any], raw: bytes) -> dict[str, Any] | None:
    """Write a managed resource under extracted/dotnet_resources/ for the nested
    analysis; Costura's ``*.compressed`` resources are deflated first."""
    import zlib
    if len(raw) < MIN_RESOURCE:
        return None
    name = x["name"]
    recipe = ["dotnet-resource", name]
    data = raw
    if name.lower().startswith("costura.") and name.lower().endswith(".compressed"):
        try:
            data = zlib.decompress(raw, -15)
            name = name[:-len(".compressed")]
            recipe.append("deflate")
            x["costura"] = True
        except zlib.error:
            pass
    safe = re.sub(r"[^\w.\-]+", "_", name).strip("._")[-100:] or "resource.bin"
    out = root / "extracted" / RES_DIR / sha[:12] / safe
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
    except OSError:
        return None
    x["stored_path"] = out.relative_to(root).as_posix()
    return {"path": str(out), "filename": safe, "origin": f".NET resource {x['name']} of {label}",
            "recipe": recipe, "source": "code-resources"}


from .resources import is_resources, parse as parse_resources  # noqa: E402


def analyze_case(root: Path, original: Path, nested_tree: list[dict[str, Any]]) -> dict[str, Any]:
    from .. import golang
    from ..codeanalysis.case import is_dotnet
    res: dict[str, Any] = {"module": "dotnet", "objects": [], "findings": [], "warnings": [], "status": "ok"}
    if not available():
        res.update(status="unavailable")
        res["warnings"].append("dnfile is not installed in the portable Python (Diagnostics → Retry tool-deps)")
        return res
    seen: set[str] = set()
    for t in golang.targets(root, original, nested_tree):
        p: Path = t["path"]
        try:
            if p.stat().st_size > MAX_SIZE:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        if not is_dotnet(data):
            continue
        sha = hashlib.sha256(data).hexdigest()
        item: dict[str, Any] = {"label": t["label"], "stored_path": t["stored_path"], "original": bool(t.get("original")),
                                "sha256": sha}
        if sha in seen:
            item["duplicate"] = True
            res["objects"].append(item)
            continue
        seen.add(sha)
        try:
            r = parse(data)
        except Exception as exc:  # noqa: BLE001  (a malformed assembly never breaks the case)
            log.warning(".NET metadata failed on %s: %s", p.name, exc)
            r = {"error": f"metadata parser: {exc}"[:300]}
        res_strings: list[tuple[str, str]] = []
        for x in r.get("resources") or []:
            raw = x.pop("_data", b"")
            if is_resources(raw):
                rs = parse_resources(raw)
                if not rs.get("error"):
                    x["entries"] = []
                    for e in rs["entries"]:
                        blob = e.pop("_data", None)
                        if e.get("type") == "string" and e.get("value"):
                            res_strings.append((f"{x['name']} › {e['name']}", e["value"]))
                        if blob:
                            e["pe"] = blob[:2] == b"MZ"
                            ext = e.get("carved") or ("exe" if e["pe"] else "bin")
                            sub = {"name": f"{x['name']}.{e['name']}.{ext}"}
                            child = _resource_child(root, sha, t["label"], sub, blob)
                            if child:
                                e["stored_path"] = sub.get("stored_path", "")
                                res.setdefault("_children", []).append(child)
                        x["entries"].append(e)
                    x["resources_format"] = f"ResourceReader v{rs['version']}, {rs['count']} entries"
                    continue
                x["resources_error"] = rs["error"]
            child = _resource_child(root, sha, t["label"], x, raw)
            if child:
                res.setdefault("_children", []).append(child)
        item["result"] = r
        cil_strings = r.pop("_cil_strings", None) or []
        located = {s for _, s in cil_strings}
        item["ioc_sources"] = (
            [{"location": f"{t['label']} › {m}", "text": s} for m, s in cil_strings[:3000]]
            + [{"location": f"{t['label']} › decrypted › {d['caller']}", "text": d["output"]}
               for d in ((r.get("cil") or {}).get("decrypted") or [])]
            + [{"location": f"{t['label']} › resources › {n}", "text": v} for n, v in res_strings[:2000]]
            + [{"location": f"{t['label']} › #US", "text": s} for s in (r.get("strings") or [])[:3000] if s not in located])
        res["objects"].append(item)
        if not r.get("error"):
            res["findings"].extend(_findings(item))
    res["_children"] = (res.get("_children") or [])[:MAX_CHILDREN]
    res["counts"] = {"objects": len(res["objects"]), "findings": len(res["findings"])}
    return res
