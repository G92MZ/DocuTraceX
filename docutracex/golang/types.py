"""Go types, interfaces, methods and source files (Go phase 2).

Two sources, merged by type name:

* GoReSym ``-t -p``: every runtime type descriptor (kind, address, a
  Go-like reconstruction with struct fields and interface methods) and the
  source file paths kept in pclntab.
* The function table: methods are named ``pkg.(*T).M`` / ``pkg.T.M``, so the
  receiver types and their methods (with addresses) come out even when
  GoReSym refuses the file.

Static only; the result goes to ``<case>/code/<sha256>.types.json``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

MAX_TYPES = 20000
_PTR_RECV = re.compile(r"^(?P<pkg>.+?)\.\(\*(?P<t>[A-Za-z_]\w*)(?:\[[^\]]*\])?\)\.(?P<m>[^.]+)$")
_VAL_RECV = re.compile(r"^(?P<pkg>(?:[^/]+/)*[^./]+)\.(?P<t>[A-Z]\w*)(?:\[[^\]]*\])?\.(?P<m>[A-Za-z_]\w*)$")
_STD_FILE = re.compile(r"(^|/)(go/src|goroot|go-build|\$GOROOT)/|^/usr/local/go/|^/usr/lib/go|^C:/Program Files/Go/"
                       r"|/hostedtoolcache/.*/go/|/x64/src/|/go/\d+\.\d+[^/]*/(x64/)?src/", re.IGNORECASE)


_ODD = re.compile(r"^(func\(|\[|map\[|chan |struct ?\{|interface ?\{|go\.shape|noalg\.|\*)")
_WRAP = re.compile(r"^(func|deferwrap|gowrap|wrap)\d+$")


def _short(name: str) -> str:
    """'github.com/a/b/pkg.T' → 'pkg.T' (GoReSym prints types with the last path element)."""
    n = name.split("[", 1)[0]
    return n[n.rfind("/") + 1:]


def methods_from_names(names: list[dict[str, Any]], known: set[str] | None = None) -> dict[str, list[dict[str, Any]]]:
    """{"pkg/path.T": [{name, method, pointer, addr}]} from the function table."""
    out: dict[str, list[dict[str, Any]]] = {}
    for f in names:
        n = f.get("name") or ""
        m = _PTR_RECV.match(n)
        ptr = bool(m)
        if not m:
            m = _VAL_RECV.match(n)
            if not m or _WRAP.match(m.group("m")):
                continue
            if known is not None and _short(f"{m.group('pkg')}.{m.group('t')}") not in known:
                continue                                  # Func.closure-like names, not a value receiver
        out.setdefault(f"{m.group('pkg')}.{m.group('t')}", []).append(
            {"name": n, "method": m.group("m"), "pointer": ptr, "addr": f.get("start")})
    return out


def build(goresym_raw: dict[str, Any] | None, names: list[dict[str, Any]], main_module: str = "") -> dict[str, Any]:
    raw = goresym_raw or {}
    user_pkgs = {_short(n["name"]).split(".", 1)[0] for n in names if n.get("user")}
    user_pkgs |= {"main"}
    full_pkg = {}                                          # short package → full import path (program code first)
    for n in sorted(names, key=lambda x: not x.get("user")):
        nm = n.get("name") or ""
        i = nm.rfind("/")
        head = nm[i + 1:].split(".", 1)[0]
        full_pkg.setdefault(head, nm[:i + 1] + head)
    types: dict[str, dict[str, Any]] = {}
    for key in ("Types", "Interfaces"):
        for t in raw.get(key) or []:
            s = t.get("Str") or ""
            base = s.lstrip("*")
            if not base or _ODD.match(base) or " " in base:
                continue
            cur = types.get(base)
            if cur is None or (s == base and cur.get("_ptr")):
                types[base] = {"name": base, "kind": t.get("Kind") or "" if s == base else "",
                               "va": t.get("VA"), "source": "GoReSym", "_ptr": s != base,
                               "reconstructed": (t.get("Reconstructed") or "")[:20000] if s == base else "",
                               "methods": []}
    known = set(types) if types else None
    for tname, ms in methods_from_names(names, known).items():
        key = _short(tname)
        t = types.setdefault(key, {"name": key, "kind": "", "va": None, "source": "method names",
                                   "reconstructed": "", "methods": []})
        t["path"] = tname
        t["methods"] = sorted(ms, key=lambda x: x["method"])
    for t in types.values():
        t.pop("_ptr", None)
        pkg = t["name"].split(".", 1)[0]
        t["package"] = t.get("path", "").rsplit(".", 1)[0] if t.get("path") else full_pkg.get(pkg, pkg)
        t["user"] = pkg in user_pkgs
        rec = t["reconstructed"]
        t["fields"] = len(re.findall(r"^[ \t]+\w[\w, ]*[ \t]+\S", rec, re.MULTILINE)) if t["kind"] == "Struct" else 0
    _implementations(types)
    ordered = sorted(types.values(), key=lambda t: (not t["user"], t["package"], t["name"]))[:MAX_TYPES]
    files = [f for f in raw.get("Files") or [] if isinstance(f, str)]
    if not files:                                        # GoReSym missing / refused: the own pclntab reader
        files = list(dict.fromkeys(n["file"] for n in names if n.get("file") and not n["file"].startswith("<")))
    user_files = [f for f in files if not _STD_FILE.search(f.replace("\\", "/")) and "/pkg/mod/" not in f.replace("\\", "/")]
    kinds: dict[str, int] = {}
    for t in ordered:
        if t["user"]:
            kinds[t["kind"] or "?"] = kinds.get(t["kind"] or "?", 0) + 1
    return {"types": ordered, "files": files[:5000], "user_files": user_files[:2000],
            "build_paths": build_paths(files),
            "summary": {"types": len(ordered), "user_types": sum(1 for t in ordered if t["user"]),
                        "interfaces": sum(1 for t in ordered if t["kind"] == "Interface"),
                        "with_methods": sum(1 for t in ordered if t["methods"]), "user_kinds": kinds,
                        "files": len(files), "user_files": len(user_files),
                        "goresym": bool(raw.get("Types") or raw.get("Interfaces"))}}


_HOME = re.compile(r"^(?:[A-Za-z]:)?/(?:home|Users|users)/([^/]+)/|^/root/", re.IGNORECASE)


def build_paths(files: list[str]) -> dict[str, Any]:
    """Where the program was built, from the source paths Go keeps (no -trimpath):
    the accounts (``/home/<user>/``, ``C:/Users/<user>/``) and the project
    directories of the program's own files. The same user / project path across
    samples is a lead to link them; it says nothing on its own."""
    users: dict[str, int] = {}
    roots: dict[str, int] = {}
    for f in files:
        g = f.replace("\\", "/")
        m = _HOME.match(g)
        if m:
            u = m.group(1) if m.lastindex else "root"
            users[u] = users.get(u, 0) + 1
        if not re.match(r"^(?:[A-Za-z]:)?/", g) or _STD_FILE.search(g) or "/pkg/mod/" in g:
            continue
        d = g.rsplit("/", 1)[0]
        roots[d] = roots.get(d, 0) + 1
    return {"users": sorted(users, key=lambda u: -users[u])[:10],
            "project_dirs": sorted(roots, key=lambda d: -roots[d])[:10],
            "trimpath": bool(files) and not any(re.match(r"^(?:[A-Za-z]:)?/", f.replace("\\", "/"))
                                                 and not _STD_FILE.search(f.replace("\\", "/")) for f in files)}


_IFACE_METHOD = re.compile(r"^\s*([A-Za-z_]\w*)\(", re.MULTILINE)


def _implementations(types: dict[str, dict[str, Any]]) -> None:
    """Go's structural typing: a type implements an interface when its method
    set covers the interface's methods (pointer receivers included)."""
    ifaces = {}
    for t in types.values():
        if t["kind"] == "Interface" and t["reconstructed"]:
            body = t["reconstructed"].split("{", 1)[-1]
            ms = set(_IFACE_METHOD.findall(body.replace("{", "\n")))
            if ms:
                ifaces[t["name"]] = ms
    for t in types.values():
        t.setdefault("implements", [])
        if t["kind"] == "Interface":
            t.setdefault("implemented_by", [])
    for t in types.values():
        have = {m["method"] for m in t.get("methods") or []}
        if not have or t["kind"] == "Interface":
            continue
        for iname, need in ifaces.items():
            if need <= have and (t["user"] or types[iname]["user"]):
                t["implements"].append(iname)
                if len(types[iname]["implemented_by"]) < 50:
                    types[iname]["implemented_by"].append(t["name"])


def types_file(root: Path, sha256: str) -> Path:
    if not sha256 or any(c not in "0123456789abcdef" for c in sha256):
        raise ValueError("bad id")
    return root / "code" / f"{sha256}.types.json"


def write(root: Path, sha256: str, result: dict[str, Any]) -> None:
    p = types_file(root, sha256)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result), encoding="utf-8")
