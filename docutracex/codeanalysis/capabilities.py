"""Capabilities justified by correlated static evidence (Go phase 9).

A capability is only reported when *code* supports it: a call to the right
Go package / API (or a crypto result) in the same function, together with at
least one more independent signal: another call, a string that function
uses, a crypto result, or the function being reachable from an entry point.
A string on its own (a "password" somewhere in the file) never raises a
capability. Each one carries its ATT&CK technique, severity, confidence, the
functions and evidence behind it, and how capa sees the same technique.
"""

from __future__ import annotations

import re
from typing import Any

# kind: "call" (callee name: Go package prefix or API substring), "string" (regex on the function's strings)
RULES: list[dict[str, Any]] = [
    {"id": "http_c2", "name": "HTTP(S) communication", "attack": "T1071.001", "severity": "medium",
     "call": [r"^net/http\.", r"internetopenurl", r"httpsendrequest", r"winhttpsendrequest", r"winhttpopenrequest",
              r"internetconnect", r"^github\.com/(go-resty|valyala/fasthttp|imroc/req)"],
     "string": [r"(?i)https?://", r"(?i)user-agent|mozilla/5\.0"]},
    {"id": "raw_socket", "name": "Raw TCP / UDP connection", "attack": "T1095", "severity": "medium",
     "call": [r"^net\.Dial", r"^net\.\(\*Dialer\)", r"^net\.Listen", r"(^|\.)wsasocket", r"(^|_)connect$", r"(^|_)socket$"],
     "string": [r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b", r"(?i)\btcp4?\b|\budp4?\b"]},
    {"id": "dns", "name": "DNS queries (possible DNS C2 / tunnelling)", "attack": "T1071.004", "severity": "medium",
     "call": [r"^net\.Lookup", r"^net\.\(\*Resolver\)\.Lookup", r"^github\.com/miekg/dns", r"dnsquery"],
     "string": [r"(?i)\btxt\b|\.onion\b|[a-z0-9-]+\.[a-z]{2,}$"]},
    {"id": "websocket", "name": "WebSocket channel", "attack": "T1071.001", "severity": "medium",
     "call": [r"^github\.com/gorilla/websocket", r"^nhooyr\.io/websocket", r"^golang\.org/x/net/websocket"],
     "string": [r"(?i)wss?://"]},
    {"id": "download_write", "name": "Download and write a file (payload drop)", "attack": "T1105", "severity": "high",
     "call": [r"^net/http\.", r"urldownloadtofile", r"internetreadfile", r"winhttpreaddata"],
     "with": [r"^os\.(WriteFile|Create|OpenFile)", r"^io/ioutil\.WriteFile", r"^io\.Copy", r"writefile", r"createfile"],
     "string": [r"(?i)\.(exe|dll|ps1|bat|vbs|bin|dat)\b"]},
    {"id": "cmd_exec", "name": "Command / process execution", "attack": "T1059", "severity": "high",
     "call": [r"^os/exec\.", r"^os\.StartProcess", r"^syscall\.(StartProcess|ForkExec|Exec)", r"createprocess",
              r"winexec", r"shellexecute", r"(^|_)system$", r"(^|_)execve$", r"(^|_)popen$"],
     "string": [r"(?i)cmd(\.exe)?\s*/c|powershell|/bin/(ba)?sh|\bwhoami\b|\bnet (user|group)\b|-enc(odedcommand)?\b"]},
    {"id": "injection", "name": "Process injection", "attack": "T1055", "severity": "high",
     "call": [r"virtualallocex", r"writeprocessmemory", r"createremotethread", r"ntcreatethreadex", r"queueuserapc",
              r"setthreadcontext", r"ntunmapviewofsection", r"golang\.org/x/sys/windows\.(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread)"],
     "string": [(r"(?i)^(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|"
                 r"NtUnmapViewOfSection|SetThreadContext|ResumeThread)$")],
     "min_calls": 2},
    {"id": "dynamic_api", "name": "Dynamic API resolution", "attack": "T1106", "severity": "medium",
     "call": [r"getprocaddress", r"ldrgetprocedureaddress", r"^syscall\.\(\*LazyDLL\)\.NewProc", r"^syscall\.NewLazyDLL",
              r"^golang\.org/x/sys/windows\.(NewLazySystemDLL|\(\*LazyDLL\)\.NewProc|LoadLibrary|GetProcAddress)",
              r"^syscall\.(LoadLibrary|GetProcAddress)"],
     "string": [r"(?i)^(kernel32|ntdll|advapi32|user32|ws2_32|wininet|amsi)(\.dll)?$", r"^[A-Z][A-Za-z]+(Ex)?[AW]?$"]},
    {"id": "run_key", "name": "Persistence: registry Run key", "attack": "T1547.001", "severity": "high",
     "call": [r"^golang\.org/x/sys/windows/registry\.", r"regsetvalue", r"regcreatekey", r"regopenkey"],
     "string": [r"(?i)currentversion\\\\?run"]},
    {"id": "sched_task", "name": "Persistence: scheduled task", "attack": "T1053.005", "severity": "high",
     "call": [r"^os/exec\.", r"createprocess", r"itaskservice", r"shellexecute"],
     "string": [r"(?i)schtasks|/create\s+/tn|\\microsoft\\windows\\"], "need_string": True},
    {"id": "service", "name": "Persistence: Windows service", "attack": "T1543.003", "severity": "high",
     "call": [r"createservice", r"^golang\.org/x/sys/windows/svc/mgr\.", r"^golang\.org/x/sys/windows/svc\.Run",
              r"^github\.com/kardianos/service"],
     "string": [r"(?i)\bsc(\.exe)?\s+create\b|binpath=|services\\"]},
    {"id": "unix_persistence", "name": "Persistence: cron / systemd / shell profile", "attack": "T1053.003", "severity": "high",
     "call": [r"^os\.(WriteFile|OpenFile|Create)", r"^io/ioutil\.WriteFile", r"^os/exec\.", r"(^|_)fopen$", r"(^|_)open$"],
     "string": [r"(?i)crontab|/etc/cron|systemd/system|\.service\b|\.bashrc|\.profile|launchagents|launchdaemons|rc\.local"],
     "need_string": True},
    {"id": "browser_creds", "name": "Credential access: browser data", "attack": "T1555.003", "severity": "high",
     "call": [r"^os\.(ReadFile|Open)", r"^io/ioutil\.ReadFile", r"cryptunprotectdata", r"sqlite", r"createfile"],
     "string": [r"(?i)login data|\bcookies\b|local state|key4\.db|logins\.json|web data|encrypted_key"],
     "need_string": True},
    {"id": "screen_capture", "name": "Screen capture", "attack": "T1113", "severity": "medium",
     "call": [r"^github\.com/kbinani/screenshot", r"^github\.com/vova616/screenshot", r"bitblt", r"getdibits",
              r"createcompatiblebitmap"],
     "string": [r"(?i)\.(png|jpe?g|bmp)\b|screenshot"]},
    {"id": "keylogging", "name": "Keylogging", "attack": "T1056.001", "severity": "high",
     "call": [r"getasynckeystate", r"setwindowshookex", r"getkeystate", r"getkeyboardstate", r"^github\.com/.*/keylogger"],
     "string": [r"(?i)\[(enter|backspace|tab|shift|ctrl)\]|keylog"]},
    {"id": "clipboard", "name": "Clipboard access", "attack": "T1115", "severity": "medium",
     "call": [r"getclipboarddata", r"openclipboard", r"^github\.com/atotto/clipboard", r"^golang\.design/x/clipboard"],
     "string": [r"(?i)clipboard|^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$|^0x[a-fA-F0-9]{40}$"]},
    {"id": "discovery", "name": "System / user discovery", "attack": "T1082", "severity": "low",
     "call": [r"^os\.Hostname", r"^os/user\.", r"^net\.Interfaces", r"getcomputername", r"getusername", r"getsysteminfo",
              r"getversionex", r"rtlgetversion", r"(^|_)uname$", r"getadaptersinfo"],
     "string": [r"(?i)hostname|username|whoami|\bos\b|arch"], "min_calls": 2},
    {"id": "ransomware", "name": "File encryption over many files (ransomware-like)", "attack": "T1486", "severity": "critical",
     "call": [r"^path/filepath\.(Walk|WalkDir)", r"^os\.ReadDir", r"^io/ioutil\.ReadDir", r"findfirstfile", r"findnextfile"],
     "with": [r"^crypto/(aes|cipher|rc4|rsa)\.", r"^golang\.org/x/crypto/(chacha20|salsa20|curve25519)", r"cryptencrypt",
              r"bcryptencrypt"],
     "string": [r"(?i)bitcoin|\bbtc\b|ransom|decrypt(ion)? (key|tool)|your files|\.onion|readme|\.locked\b|\.enc\b"]},
    {"id": "anti_analysis", "name": "Anti-debugging / anti-VM checks", "attack": "T1622", "severity": "medium",
     "call": [r"isdebuggerpresent", r"checkremotedebuggerpresent", r"ntqueryinformationprocess", r"outputdebugstring",
              r"(^|_)ptrace$", r"gettickcount", r"queryperformancecounter"],
     "string": [r"(?i)vbox|virtualbox|vmware|qemu|sandboxie|wireshark|procmon|x64dbg|ollydbg|ida(64)?\.exe|tracerpid"]},
    {"id": "self_delete", "name": "Self-deletion", "attack": "T1070.004", "severity": "medium",
     "call": [r"^os\.Executable"], "with": [r"^os\.Remove", r"deletefile", r"movefileex"],
     "string": [r"(?i)cmd(\.exe)?\s*/c\s+(ping|timeout|choice).*del\b|\bdel\s+/f"]},
]
for r in RULES:
    r["_call"] = [re.compile(p, re.IGNORECASE) for p in r["call"]]
    r["_with"] = [re.compile(p, re.IGNORECASE) for p in r.get("with", [])]
    r["_string"] = [re.compile(p) for p in r.get("string", [])]
SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _norm(n: str) -> str:
    """'imp.KERNEL32.dll_VirtualAllocEx' → 'virtualallocex' for API matching; Go names unchanged."""
    if n.lower().startswith("imp."):
        n = n[4:]
        n = n.rsplit("_", 1)[-1] if ".dll_" in n.lower() else n
        return n.lower()
    return n


def _reachable(graph: dict[str, Any]) -> dict[Any, list[Any]]:
    """Function → shortest path from a root (entry / init / uncalled program code)."""
    from collections import deque
    adj: dict[Any, list] = {}
    for e in graph.get("edges") or []:
        adj.setdefault(e["from"], []).append(e["to"])
    prev: dict[Any, Any] = {r: None for r in graph.get("roots") or []}
    q = deque(graph.get("roots") or [])
    while q:
        u = q.popleft()
        for v in adj.get(u, []):
            if v not in prev:
                prev[v] = u
                q.append(v)

    def path(x: Any) -> list[Any]:
        out = []
        while x is not None:
            out.append(x)
            x = prev[x]
        return out[::-1]
    return {k: path(k) for k in prev}


def analyze(full: dict[str, Any], graph: dict[str, Any], capa: dict[str, Any] | None = None) -> dict[str, Any]:
    fns = full.get("functions") or []
    by = {f["addr"]: f for f in fns}
    crypto = full.get("crypto") or {}
    decrypted_in = {p["function"] for p in crypto.get("plaintexts") or []}
    crypto_fns = {f["name"] for f in crypto.get("functions") or []}
    reach = _reachable(graph)
    caps: dict[str, dict[str, Any]] = {}
    for f in fns:
        if not f.get("user", True):
            continue
        # the function itself plus the analysed functions it calls directly (thin wrappers)
        callees = [n for n in f.get("callee_names") or []]
        via = list(f.get("calls") or []) + [t for ic in full.get("interface_calls") or [] if ic["from"] == f["addr"]
                                            for t in ic["targets"]]
        for c in via:
            if c in by and by[c].get("user", True):
                callees += by[c].get("callee_names") or []
        names = list(dict.fromkeys(callees))
        strs = [s["value"] for s in f.get("strings") or []] + [s["value"] for s in f.get("floss") or []]
        for rule in RULES:
            calls = sorted({n for n in names if any(rx.search(_norm(n)) for rx in rule["_call"])})
            if len(calls) < rule.get("min_calls", 1):
                continue
            ev: list[dict[str, str]] = [{"kind": "call", "detail": n} for n in calls[:6]]
            if rule["_with"]:
                w = sorted({n for n in names if any(rx.search(_norm(n)) for rx in rule["_with"])})
                if not w:
                    continue                                      # the second half of the behaviour is missing
                ev += [{"kind": "call", "detail": n} for n in w[:4]]
            hits = [s for s in strs if any(rx.search(s) for rx in rule["_string"])]
            if rule.get("need_string") and not hits:
                continue
            ev += [{"kind": "string", "detail": s[:120]} for s in hits[:4]]
            if f["name"] in decrypted_in and rule["id"] in ("http_c2", "raw_socket", "dns", "websocket"):
                ev.append({"kind": "crypto", "detail": "decrypts its configuration statically"})
            if f["name"] in crypto_fns and rule["id"] == "ransomware":
                ev.append({"kind": "crypto", "detail": "uses an encryption routine"})
            path = reach.get(f["addr"])
            if path and len(path) > 1:
                ev.append({"kind": "reachable", "detail": " → ".join((by.get(a) or {}).get("name", str(a)) for a in path)})
            kinds = {e["kind"] for e in ev}
            # independent signals: each distinct call, the strings, a crypto result (reachability only adds confidence)
            distinct = len({e["detail"] for e in ev if e["kind"] == "call"}) + len(kinds & {"string", "crypto"})
            if distinct < 2:
                continue                                          # one call alone is not a capability
            conf = "high" if distinct >= 3 or "reachable" in kinds else "medium"
            c = caps.setdefault(rule["id"], {"id": rule["id"], "name": rule["name"], "attack": rule["attack"],
                                             "severity": rule["severity"], "confidence": "medium", "functions": []})
            if conf == "high":
                c["confidence"] = "high"
            c["functions"].append({"addr": f["addr"], "name": f["name"], "confidence": conf, "evidence": ev})
    # decoding / decryption of embedded data, proven by the static decryption itself
    for p in crypto.get("plaintexts") or []:
        f = next((x for x in fns if x["name"] == p["function"]), None)
        if f is None:
            continue
        c = caps.setdefault("decode", {"id": "decode", "name": "Decrypts / decodes embedded data (configuration, payload)",
                                       "attack": "T1140", "severity": "medium", "confidence": "high", "functions": []})
        ev = [{"kind": "crypto", "detail": f"{p['method']}: {p.get('size', len(p.get('plaintext') or b''))} bytes"}]
        ev += [{"kind": "call", "detail": n} for n in (f.get("callee_names") or [])[:3]]
        if f["name"] not in [x["name"] for x in c["functions"]]:
            c["functions"].append({"addr": f["addr"], "name": f["name"], "confidence": "high", "evidence": ev})
    out = sorted(caps.values(), key=lambda c: (-SEV_ORDER[c["severity"]], c["confidence"] != "high", c["name"]))
    for c in out:
        c["functions"].sort(key=lambda x: x["confidence"] != "high")
        c["functions"] = c["functions"][:20]
    # contrast with capa (same binary): by ATT&CK technique (parent technique matches sub-techniques)
    capa_caps = (capa or {}).get("capabilities") or []
    capa_ids = {a["id"]: c["name"] for c in capa_caps for a in c.get("attack") or [] if a.get("id")}
    mine = {c["attack"] for c in out}
    for c in out:
        base = c["attack"].split(".")[0]
        both = [n for i, n in capa_ids.items() if i == c["attack"] or i.split(".")[0] == base]
        c["capa"] = both[:3] if capa_caps else None
    capa_only = sorted({(i, n) for i, n in capa_ids.items()
                        if i not in mine and i.split(".")[0] not in {m.split(".")[0] for m in mine}})
    return {"capabilities": out, "capa_available": bool(capa_caps), "capa_status": (capa or {}).get("status"),
            "capa_only": [{"attack": i, "name": n} for i, n in capa_only][:50]}


def findings(caps: dict[str, Any], label: str) -> list[dict[str, Any]]:
    """High-confidence capabilities not already covered by capa become findings."""
    out = []
    for c in caps.get("capabilities") or []:
        if c["confidence"] != "high" or c.get("capa"):
            continue
        fn = c["functions"][0]
        out.append({"rule": f"code:cap:{c['id']}", "severity": c["severity"], "tool": "code analysis",
                    "detail": f"{c['name']} ({c['attack']}) in {fn['name']}",
                    "location": label, "evidence": "; ".join(e["detail"] for e in fn["evidence"][:4]),
                    "attack": c["attack"]})
    return out
