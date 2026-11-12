"""Inno Setup's compiled ``[Code]``: the RemObjects Pascal Script bytecode (``IFPS``)
that innounp extracts as ``embedded/CompiledCode.bin``.

The script is where an installer does its own work — a downloader asks a server
what to fetch, downloads and runs it, writes the registry… Statically, without
running or decompiling anything:

- its **strings** (ANSI and UTF-16 constants): URLs, hosts, paths, registry keys,
  command lines — mined for IOCs;
- the **functions it calls**: Inno Setup's own (``DownloadTemporaryFile``, ``Exec``,
  ``ShellExec``, ``RegWriteStringValue``…, stored by name in upper case) and the
  Windows APIs it imports from DLLs (``external 'URLDownloadToFileW@urlmon.dll'``,
  stored as ``dll:urlmon.dll`` + the function name);
- findings for what those calls do: download, execute, write the registry, load
  DLLs, download plug-ins (Inno Download Plugin, InnoTools Downloader).
"""

from __future__ import annotations

import re
from typing import Any

MAGIC = b"IFPS"
MAX_STRINGS = 4000

_ASCII = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_DLL = re.compile(rb"dll:([\x20-\x7e]{1,128}?)\x00([\x20-\x7e]{1,128}?)\x00")
_AT_DLL = re.compile(r"\b([A-Za-z_][\w]{2,64})@([\w.\-]{1,64}\.dll)\b", re.IGNORECASE)

# behaviour → (severity, ATT&CK, Inno built-ins / Windows APIs, case-insensitive)
_BEHAVIOUR = {
    "download": ("medium", "T1105", (
        "DownloadTemporaryFile", "DownloadTemporaryFileSize", "DownloadTemporaryFileDate", "CreateDownloadPage",
        "URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileW", "InternetOpenUrlA",
        "InternetOpenUrlW", "InternetReadFile", "HttpSendRequestW", "WinHttpOpen", "WinHttpSendRequest",
        "WinHttpReadData", "idpAddFile", "idpDownloadAfter", "idpDownloadFiles", "ITD_AddFile",
        "ITD_DownloadFiles", "ITD_DownloadAfter")),
    "execute": ("medium", "T1204.002", (
        "Exec", "ExecAsOriginalUser", "ShellExec", "ShellExecAsOriginalUser", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExW", "CreateProcessA", "CreateProcessW", "WinExec")),
    "registry": ("low", "T1112", (
        "RegWriteStringValue", "RegWriteExpandStringValue", "RegWriteMultiStringValue", "RegWriteDWordValue",
        "RegWriteBinaryValue", "RegDeleteValue", "RegDeleteKeyIncludingSubkeys", "RegSetValueExW",
        "RegCreateKeyExW")),
    "load_dll": ("low", "T1129", ("LoadDLL", "LoadLibraryA", "LoadLibraryW", "GetProcAddress")),
    "files": ("info", "", ("ExtractTemporaryFile", "ExtractTemporaryFiles", "SaveStringToFile",
                           "SaveStringsToFile", "SaveStringsToUTF8File", "FileCopy", "DeleteFile", "DelTree")),
}
_SAYS = {"download": "downloads files from the Internet", "execute": "runs programs",
         "registry": "writes the registry", "load_dll": "loads DLLs / resolves functions at run time",
         "files": "writes / extracts / deletes files"}


def is_ifps(data: bytes) -> bool:
    return data[:4] == MAGIC


def _strings(data: bytes) -> list[str]:
    out = [m.group(0).decode("ascii") for m in _ASCII.finditer(data)]
    out += [m.group(0).decode("utf-16-le") for m in _UTF16.finditer(data)]
    return list(dict.fromkeys(s.strip() for s in out if s.strip()))[:MAX_STRINGS]


def analyze(data: bytes, name: str = "CompiledCode.bin") -> dict[str, Any]:
    res: dict[str, Any] = {"module": "ifps", "file": name, "size": len(data), "findings": []}
    if not is_ifps(data):
        res.update(status="not_applicable", detail="not Pascal Script bytecode (no IFPS header)")
        return res
    res["version"] = int.from_bytes(data[4:8], "little") if len(data) >= 8 else None
    strings = _strings(data)
    imports = [{"dll": d.decode(), "function": f.decode()} for d, f in _DLL.findall(data)]
    for s in strings:
        for fn, dll in _AT_DLL.findall(s):
            imports.append({"dll": dll, "function": fn})
    seen: set[tuple[str, str]] = set()
    imports = [i for i in imports if (k := (i["dll"].lower(), i["function"])) not in seen and not seen.add(k)]
    words = {s.lower() for s in strings} | {i["function"].lower() for i in imports}
    uses: dict[str, list[str]] = {}
    for what, (_sev, _att, names) in _BEHAVIOUR.items():
        hit = [n for n in names if n.lower() in words]
        if hit:
            uses[what] = hit
    res.update(status="ok", strings=strings, imports=imports, uses=uses,
               counts={"strings": len(strings), "imports": len(imports)})
    loc = f"file:{name}"
    for what, hit in uses.items():
        sev, att, _ = _BEHAVIOUR[what]
        res["findings"].append({
            "tool": "ifps", "rule": f"ifps_{what}", "severity": sev,
            "detail": f"Inno Setup [Code] {_SAYS[what]}: {', '.join(hit[:8])}" + (f" · {att}" if att else ""),
            "location": loc, "evidence": ", ".join(hit[:12])})
    if "download" in uses and "execute" in uses:
        res["findings"].append({
            "tool": "ifps", "rule": "ifps_download_execute", "severity": "medium",
            "detail": "Inno Setup [Code] both downloads and runs programs: a downloader installer — what it "
                      "fetches is decided at run time (URLs below, if any are constants) · T1105",
            "location": loc, "evidence": ""})
    if imports:
        res["findings"].append({
            "tool": "ifps", "rule": "ifps_dll_imports", "severity": "info",
            "detail": f"{len(imports)} function(s) imported from DLLs: "
                      + ", ".join(f"{i['function']}@{i['dll']}" for i in imports[:10]),
            "location": loc, "evidence": ""})
    res["counts"]["findings"] = len(res["findings"])
    return res
