"""Portable interpreters shipped inside an archive, folder or installer.

A lure that wants to run a script without depending on what the victim has
installed brings its own interpreter: the Python "embeddable" runtime
(``pythonw.exe`` + ``python3XX._pth`` / ``.zip`` / ``.dll``), ``node.exe``, a
private JRE (``javaw.exe`` + ``jvm.dll``), ``AutoIt3.exe`` with a ``.a3x``,
portable Ruby / Perl / PHP / Lua / Tcl / PowerShell 7… The script it runs often
has a harmless-looking name (``notes.html``, ``readme.txt``), so the
interpreter itself is the signal: this module names it, what it can run and
who launches it. Pure listing and text reading: nothing is executed.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

# language → (interpreter executables, runtime files of a portable copy, script extensions)
CATALOGUE: dict[str, tuple[set[str], re.Pattern[str], set[str]]] = {
    "Python": ({"python.exe", "pythonw.exe", "python3.exe"},
               re.compile(r"^python3?\d*(?:\._pth|\.zip|\.dll)$|^pythonw?\d*\.exe$|^vcruntime140\.dll$"),
               {".py", ".pyw", ".pyc", ".pyz", ".pyzw"}),
    "Node.js": ({"node.exe"}, re.compile(r"^node\.(?:exe|dll|lib)$|^npm(?:\.cmd)?$|^node_modules$"),
                {".js", ".mjs", ".cjs", ".jse"}),
    "Deno": ({"deno.exe"}, re.compile(r"^deno\.exe$"), {".js", ".ts", ".mjs"}),
    "Bun": ({"bun.exe"}, re.compile(r"^bun\.exe$"), {".js", ".ts", ".mjs"}),
    "Java": ({"java.exe", "javaw.exe"}, re.compile(r"^(?:jvm|java|jli|verify|zip)\.dll$|^modules$|^rt\.jar$|^release$"),
             {".jar", ".class"}),
    "AutoIt": ({"autoit3.exe", "autoit3_x64.exe", "autoit3a.exe"}, re.compile(r"^autoit3(?:_x64|a)?\.exe$"),
               {".a3x", ".au3"}),
    "AutoHotkey": ({"autohotkey.exe", "autohotkey64.exe", "autohotkey32.exe", "autohotkeyu64.exe",
                    "autohotkeyu32.exe", "autohotkeya32.exe"}, re.compile(r"^autohotkey\w*\.exe$"), {".ahk"}),
    "Lua": ({"lua.exe", "wlua.exe", "luajit.exe", "lua5.1.exe", "lua54.exe", "lua53.exe"},
            re.compile(r"^lua\d*(?:\.\d+)?\.dll$|^luajit\.dll$"), {".lua", ".luac"}),
    "Ruby": ({"ruby.exe", "rubyw.exe"}, re.compile(r"^x64-(?:msvcrt|ucrt)-ruby\d+\.dll$|^msvcrt-ruby\d+\.dll$"),
             {".rb", ".rbw"}),
    "Perl": ({"perl.exe", "wperl.exe"}, re.compile(r"^perl5\d+\.dll$"), {".pl", ".pm", ".plx"}),
    "PHP": ({"php.exe", "php-win.exe", "php-cgi.exe"}, re.compile(r"^php\d*(?:ts)?\.dll$|^php\.ini$"), {".php", ".phar"}),
    "Tcl": ({"tclsh.exe", "wish.exe"} | {f"tclsh8{i}.exe" for i in range(4, 8)} | {f"wish8{i}.exe" for i in range(4, 8)},
            re.compile(r"^tcl8\d+t?\.dll$|^tk8\d+t?\.dll$"), {".tcl", ".tk"}),
    "PowerShell 7": ({"pwsh.exe"}, re.compile(r"^pwsh\.dll$|^system\.management\.automation\.dll$"), {".ps1", ".psm1"}),
    "R": ({"rscript.exe", "r.exe"}, re.compile(r"^r\.dll$"), {".r"}),
    "Julia": ({"julia.exe"}, re.compile(r"^libjulia\.dll$"), {".jl"}),
}
# run without a console window: nothing shows on screen while the script runs
WINDOWLESS = {"pythonw.exe", "javaw.exe", "rubyw.exe", "wperl.exe", "php-win.exe", "wlua.exe", "wish.exe",
              "autoit3.exe", "autoit3_x64.exe"} | {e for e in CATALOGUE["AutoHotkey"][0]}
_LAUNCHERS = {".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".lnk", ".url", ".inf", ".sct"}
_LAUNCH_READ = 256 * 1024


def _base(name: str) -> str:
    return PurePosixPath(name.replace("\\", "/")).name.lower()


_ALL_EXES = {e for exes, _rt, _ex in CATALOGUE.values() for e in exes}
_ORIG_FN = re.compile("OriginalFilename".encode("utf-16-le") + rb"(?:\x00\x00){1,3}((?:[\x20-\x7e]\x00){3,64})")
_SNIFF_MAX = 64 * 1024 * 1024


def original_filename(path: str | Path) -> str | None:
    """The OriginalFilename of a PE's version information (``AutoIt3.exe`` even when
    the file is called ``svchost-update.exe``), lower-cased; None if absent."""
    try:
        p = Path(path)
        if p.stat().st_size > _SNIFF_MAX:
            return None
        raw = p.read_bytes()
    except OSError:
        return None
    if raw[:2] != b"MZ":
        return None
    m = _ORIG_FN.search(raw, max(0, len(raw) - 4 * 1024 * 1024))
    return m.group(1).decode("utf-16-le").strip().lower() if m else None


_NOT_PE = {".txt", ".ini", ".json", ".xml", ".html", ".htm", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".py", ".ahk",
           ".au3", ".lnk", ".url", ".png", ".jpg", ".gif", ".ico", ".pdf", ".zip", ".pyc", ".a3x", ".pth"}


def _has_export(path: str, name: str) -> bool:
    """The PE at ``path`` exports ``name`` (by name)."""
    try:
        import pefile
        if Path(path).stat().st_size > _SNIFF_MAX:
            return False
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        return any((e.name or b"").decode("latin-1") == name
                   for e in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or [])
    except Exception:  # noqa: BLE001
        return False


def _a3x(path: str | None) -> bool:
    if not path:
        return False
    try:
        with open(path, "rb") as fh:
            head = fh.read(24)
    except OSError:
        return False
    from .parsers.autoit import is_a3x
    return is_a3x(head)


def bundle(entries: list[tuple[str, str | None]]) -> list[dict[str, Any]]:
    """The interpreters an archive / folder / installer ships: ``entries`` are
    (name or path inside it, local file or None). One record per language.
    Renamed interpreters are recognised by the OriginalFilename of their version
    information, compiled AutoIt scripts (.a3x) by their content."""
    names = [(n, _base(n), f) for n, f in entries if n]
    # what each renamed executable really is
    real: dict[str, str] = {}
    for n, b, f in names:
        # any name, extension or none: a random name without extension can be AutoHotkey.exe
        if f and b not in _ALL_EXES and not PurePosixPath(b).suffix in _NOT_PE:
            orig = original_filename(f)
            if orig in _ALL_EXES:
                real[b] = orig
    a3x = [n for n, b, f in names if not b.endswith(".a3x") and _a3x(f)]
    # scripts of a language recognised by their content (renamed, no extension)
    from .parsers import genscript
    by_content: dict[str, list[tuple[str, str]]] = {}
    for n, b, f in names:
        if not f or PurePosixPath(b).suffix.lower() in genscript.LANGS:
            continue
        try:
            if Path(f).stat().st_size > genscript.SNIFF_MAX:
                continue
        except OSError:
            continue
        text = genscript._text_of(Path(f))
        lang_c = genscript.sniff(text) if text else None
        if lang_c:
            by_content.setdefault(lang_c, []).append((n, f))
    files = {b: (n, f) for n, b, f in names}
    shown = {b: PurePosixPath(n.replace("\\", "/")).name for n, b, _f in names}   # names as written
    out = []
    for lang, (exes, runtime, exts) in CATALOGUE.items():
        found = sorted({b for _n, b, _f in names if b in exes})
        renamed = sorted(f"{shown.get(b, b)} (really {real[b]})" for b in real if real[b] in exes)
        if not found and not renamed:
            continue
        found += [b for b in real if real[b] in exes]
        rt = sorted({b for _n, b, _f in names if runtime.search(b) and b not in exes and b not in real})
        scripts = [n for n, b, _f in names if PurePosixPath(b).suffix in exts][:50]
        if lang == "AutoIt":
            scripts += a3x[:20]
        sniffed = [n for n, _f in by_content.get(lang, [])]
        scripts += [n for n in sniffed if n not in scripts]
        # libraries those scripts load from the bundle (DllCall("payload.dat\\Export"))
        loads = []
        for n, f in [(n, f) for n, b, f in names if n in scripts and f]:
            text = genscript._text_of(Path(f)) or ""
            for c in genscript.dll_calls(text):
                hit = files.get(c["file"].lower())
                if hit:
                    loads.append({"script": n, "library": hit[0], "export": c["export"],
                                  "exported": _has_export(hit[1], c["export"]) if c["export"] else None})
        # launchers that name one of the interpreters (run.bat: "pythonw.exe notes.html")
        exe_re = re.compile("|".join(re.escape(e) for e in found), re.I)
        launchers, disguised = [], []
        for n, b, f in names:
            if PurePosixPath(b).suffix not in _LAUNCHERS or not f:
                continue
            try:
                raw = Path(f).read_bytes()[:_LAUNCH_READ]
            except OSError:
                continue
            text = raw.decode("utf-16-le", "ignore") if raw[:2] == b"\xff\xfe" or b"\x00" in raw[:64] else raw.decode("latin-1")
            text = re.sub(r"%~[a-z]*\d", "", text)          # %~dp0pythonw.exe → pythonw.exe
            m = exe_re.search(text)
            if not m:
                continue
            line = text[max(0, text.rfind("\n", 0, m.start()) + 1):m.end() + 160].split("\n")[0].strip()
            launchers.append(f"{n}: {line[:200]}")
            # what the launcher hands the interpreter: a file in the bundle whose extension is not the language's
            arg = re.search(r"[\w\-. ]+\.(\w{1,6})\b", text[m.end():m.end() + 300])
            if arg and f".{arg.group(1).lower()}" not in exts and not arg.group(0).strip().lower().endswith(".exe"):
                disguised.append(arg.group(0).strip())
        out.append({"language": lang, "interpreters": sorted({shown.get(b, b) for b in found}), "runtime": rt, "scripts": scripts,
                    "launchers": launchers[:10], "disguised": sorted(set(disguised))[:10],
                    "windowless": sorted({real.get(b, b) for b in found} & WINDOWLESS),
                    "renamed": renamed, "compiled_scripts": a3x[:20] if lang == "AutoIt" else [],
                    "sniffed": sniffed, "loads": loads[:10]})
    return out


def findings(entries: list[tuple[str, str | None]], where: str, container: str = "archive") -> list[dict[str, Any]]:
    out = []
    for rec in bundle(entries):
        lang = rec["language"]
        portable = bool(rec["runtime"])
        what = f"embedded {lang} interpreter ({', '.join(rec['interpreters'])}"
        what += f", portable runtime: {', '.join(rec['runtime'][:4])})" if portable else ")"
        parts = [f"{what} shipped in the {container}"]
        if rec["renamed"]:
            parts.append(f"renamed: {', '.join(rec['renamed'][:3])}")
        if rec["compiled_scripts"]:
            parts.append(f"compiled AutoIt script(s) under other names: "
                         f"{', '.join(PurePosixPath(s).name for s in rec['compiled_scripts'][:3])}")
        if rec["windowless"]:
            parts.append(f"{', '.join(rec['windowless'])} runs without a window")
        if rec["launchers"]:
            parts.append(f"launched by {len(rec['launchers'])} file(s) in it")
        compiled = {PurePosixPath(c).name.lower() for c in rec["compiled_scripts"]}
        rec["disguised"] = [d for d in rec["disguised"] if d.lower() not in compiled]
        if rec["disguised"]:
            parts.append(f"on a file that does not look like {lang}: {', '.join(rec['disguised'][:3])}")
        if rec["sniffed"]:
            parts.append(f"{lang} script(s) without their extension: "
                         f"{', '.join(PurePosixPath(s).name for s in rec['sniffed'][:3])}")
        for ld in rec["loads"][:3]:
            ex = f"'s export {ld['export']}" + (" (present in its export table)" if ld["exported"] else "") if ld["export"] else ""
            parts.append(f"{PurePosixPath(ld['script']).name} loads {PurePosixPath(ld['library']).name}{ex} — "
                         "a DLL side-loaded through the interpreter")
        if rec["scripts"]:
            parts.append(f"{len(rec['scripts'])} {lang} file(s) it can run: {', '.join(PurePosixPath(s).name for s in rec['scripts'][:5])}")
        high = bool(rec["launchers"] or rec["disguised"] or rec["renamed"] or rec["compiled_scripts"] or rec["loads"]
                    or (rec["windowless"] and (rec["scripts"] or portable)))
        ev = "\n".join(["interpreters: " + ", ".join(rec["interpreters"]),
                        "runtime: " + (", ".join(rec["runtime"]) or "-"),
                        "scripts: " + (", ".join(rec["scripts"][:20]) or "-")]
                       + [f"launcher {x}" for x in rec["launchers"]]
                       + [f"{ld['script']} → DllCall {ld['library']}\\{ld['export']}" for ld in rec["loads"]])
        out.append({"tool": container, "rule": f"embedded_interpreter_{re.sub(r'[^a-z0-9]+', '', lang.lower())}",
                    "severity": "high" if high else "medium", "detail": " — ".join(parts),
                    "location": where, "evidence": ev, "attack": "T1059"})
    return out
