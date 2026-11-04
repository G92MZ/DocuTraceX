"""Which functions deserve a closer look (and decompilation first).

A function scores by what it calls (Go packages / Windows APIs / libc), the
strings it uses and its shape (loops with XOR). The categories follow the Go
roadmap: communications, crypto, command execution, process manipulation,
persistence, files, data transformation, initialisation, and unknown code
calling any of those. Every point comes with its reason.
"""

from __future__ import annotations

import re
from typing import Any

CATEGORIES: dict[str, dict[str, Any]] = {
    "network": {"weight": 30, "label": "communications",
                "go": ("net.", "net/http.", "net/url.", "crypto/tls.", "net/smtp.", "golang.org/x/net",
                       "github.com/gorilla/websocket", "nhooyr.io/websocket", "github.com/miekg/dns"),
                "api": ("internet", "http", "winhttp", "urldownload", "wsastartup", "socket", "connect", "send",
                        "recv", "getaddrinfo", "gethostbyname", "dnsquery", "ftpput", "ftpget", "curl_easy")},
    "crypto": {"weight": 25, "label": "cryptography",
               "go": ("crypto/aes.", "crypto/cipher.", "crypto/rc4.", "crypto/des.", "crypto/rsa.", "crypto/ecdh.",
                      "crypto/ecdsa.", "crypto/ed25519.", "crypto/hmac.", "crypto/sha256.", "golang.org/x/crypto"),
               "api": ("crypt", "bcrypt", "ncrypt", "rc4", "aes")},
    "exec": {"weight": 30, "label": "command execution",
             "go": ("os/exec.", "os.StartProcess", "syscall.StartProcess", "syscall.ForkExec", "syscall.Exec"),
             "api": ("createprocess", "winexec", "shellexecute", "system", "execve", "popen", "fork")},
    "process": {"weight": 35, "label": "process manipulation / injection",
                "go": ("syscall.(*LazyProc)", "golang.org/x/sys/windows.VirtualAlloc", "golang.org/x/sys/windows.OpenProcess",
                       "golang.org/x/sys/windows.WriteProcessMemory", "golang.org/x/sys/windows.CreateRemoteThread"),
                "api": ("virtualalloc", "virtualprotect", "writeprocessmemory", "readprocessmemory", "createremotethread",
                        "ntcreatethreadex", "queueuserapc", "setthreadcontext", "openprocess", "ntunmapviewofsection",
                        "mapviewofsection", "ptrace", "mprotect")},
    "persistence": {"weight": 25, "label": "persistence",
                    "go": ("golang.org/x/sys/windows/registry.", "golang.org/x/sys/windows/svc", "os.UserConfigDir"),
                    "api": ("regsetvalue", "regcreatekey", "createservice", "startservice", "schtasks", "itaskservice"),
                    "strings": (r"currentversion\\run", r"\\startup\\", "schtasks", "crontab", "systemd", ".bashrc",
                                "launchagents")},
    "files": {"weight": 10, "label": "file operations",
              "go": ("os.WriteFile", "os.Create", "os.OpenFile", "os.Remove", "os.Rename", "io/ioutil.WriteFile",
                     "path/filepath.Walk", "os.ReadDir"),
              "api": ("createfile", "writefile", "deletefile", "movefile", "copyfile", "findfirstfile", "unlink")},
    "transform": {"weight": 15, "label": "data transformation",
                  "go": ("encoding/base64.", "encoding/hex.", "compress/", "encoding/binary."),
                  "api": ("rtldecompress", "cryptstringtobinary")},
    "recon": {"weight": 10, "label": "environment reconnaissance",
              "go": ("os.Hostname", "os/user.", "runtime.GOOS", "net.Interfaces", "os.Getenv"),
              "api": ("getcomputername", "getusername", "getversion", "getsysteminfo", "isdebuggerpresent",
                      "checkremotedebugger", "getadaptersinfo")},
}
URL = re.compile(r"(?i)\b(?:https?|ftp|wss?)://[\w.-]+|(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{2,5})?(?![\d.])|\.onion\b")


def _api_name(callee: str) -> str:
    """'sym.imp.KERNEL32.dll_VirtualAlloc' / 'go.syscall.Syscall' → lower-case API."""
    n = callee.lower()
    for p in ("sym.imp.", "imp.", "sub."):
        n = n.removeprefix(p)
    return n.rsplit("_", 1)[-1] if ".dll_" in n else n


def score(fn: dict[str, Any], callee_names: list[str], strings: list[str], mode: str) -> tuple[int, list[str], list[str]]:
    pts = 0
    reasons: list[str] = []
    cats: list[str] = []
    for key, c in CATEGORIES.items():
        hit = None
        for name in callee_names:
            if mode == "go" and name.startswith(c.get("go", ())):
                hit = name
                break
            api = _api_name(name)
            if any(a in api for a in c.get("api", ())) and (mode != "go" or "syscall" in name or "windows" in name):
                hit = name
                break
        if hit is None and c.get("strings"):
            hit = next((s for s in strings if any(re.search(p, s.lower()) for p in c["strings"])), None)
        if hit:
            pts += c["weight"]
            cats.append(key)
            reasons.append(f"{c['label']}: {hit[:80]}")
    urls = [s for s in strings if URL.search(s)]
    if urls:
        pts += 20
        reasons.append(f"uses URL / IP strings: {urls[0][:80]}")
        if "network" not in cats:
            cats.append("network")
    if fn.get("loops") and (fn.get("xor_ops", 0) >= 2 or fn.get("xor_keys")):
        pts += 15
        key = f", key 0x{fn['xor_keys'][0]:x}" if fn.get("xor_keys") else ""
        reasons.append(f"loop with {fn.get('xor_ops', 0)} XOR instruction(s){key} (decoding?)")
        if "transform" not in cats:
            cats.append("transform")
    name = fn.get("name", "")
    if name.endswith((".init", ".init.0")) or name in ("main.main", "main"):
        pts += 10
        reasons.append("entry / initialisation")
    if not fn.get("named") and cats:
        pts += 10
        reasons.append("unnamed function with relevant behaviour")
    size = fn.get("size") or 0
    if 64 < size <= 24000:                       # huge init tables are not more interesting
        pts += min(10, size // 400)
    return pts, reasons, cats
