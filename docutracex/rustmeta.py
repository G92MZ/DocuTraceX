"""What a Rust binary says about how it was built.

Rust binaries keep, in clear, the paths of the source files of every crate they were
built with (panic locations, ``file!()``): from them come

- the **compiler**: ``/rustc/<commit>/library/...`` (the rustc commit; FLOSS's table, when
  installed, turns it into a version) or ``rustc/1.74.0``;
- the **crates** and their versions: ``.cargo/registry/src/<index>/<crate>-<version>/`` (and
  git dependencies, ``.cargo/git/checkouts/<repo>-<hash>/``) — what the binary is made of:
  an HTTP client, encryption, string obfuscation, screen capture…;
- the **author's machine**: the home folder those paths live in (``C:\\Users\\<user>\\.cargo``,
  ``/home/<user>/``) and the project's own source paths (``…\\<project>\\src\\main.rs``), which
  relate samples built on the same machine.

Read straight from the file's bytes (regular expressions; no tool), so it works on the
strings even when they are glued together. Static only: nothing is executed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

MAX_BYTES = 128 * 1024 * 1024

_COMMIT = re.compile(rb"/rustc/([0-9a-f]{40})[\\/]library")
_VERSION = re.compile(rb"rustc/(\d{1,2}\.\d{1,3}\.\d{1,3})[\\/]")
_SEP = rb"[\\/]"
_REGISTRY = re.compile(rb"\.cargo" + _SEP + rb"registry" + _SEP + rb"src" + _SEP + rb"[^\\/\x00]{1,80}" + _SEP
                       + rb"([A-Za-z0-9_][A-Za-z0-9_\-]{0,63}?)-(\d{1,4}\.\d{1,4}\.\d{1,4}(?:-[0-9A-Za-z.\-]{1,40})?)"
                       + _SEP)
_GIT = re.compile(rb"\.cargo" + _SEP + rb"git" + _SEP + rb"checkouts" + _SEP + rb"([A-Za-z0-9_\-]{1,64})-([0-9a-f]{6,16})"
                  + _SEP)
_HOME = re.compile(rb"(?:([A-Za-z]):\\(?:Users|Documents and Settings)\\([^\\/\x00:*?\"<>|]{1,64})\\"
                   rb"|/(?:home|Users)/([^/\x00]{1,64})/|/(root)/)")
# a source path of the project itself: absolute (outside .cargo / rustc / the toolchain) or
# relative (src/…, as rustc writes the crate being built), ending in .rs. Rust glues its
# strings together, so each path is looked for in the stretch since the previous ".rs"
# (or NUL), from its LAST root (a drive or a Unix home) — never across two strings.
_RS_END = re.compile(rb"\.rs(?!rc)")             # (glued: the next string may start with a letter; not .rsrc)
_ROOT = re.compile(rb"[A-Za-z]:\\|/(?:home|Users|root|tmp|opt|mnt|builds|workspace)/")
_REL_TAIL = re.compile(rb"((?:[A-Za-z0-9_\-]{1,64}[\\/]){0,4}src[\\/][A-Za-z0-9_\-\\/.]{1,160}\.rs)$")
_PATH_OK = re.compile(rb"^[^\x00\"<>|*?\r\n]+$")
_TOOLCHAIN = re.compile(r"(?i)[\\/]\.cargo[\\/]|[\\/]\.rustup[\\/]|/rustc/|[\\/]rustc[\\/]|[\\/]library[\\/](?:std|core|alloc)[\\/]")

# what a crate says about the binary (the crates a malware author reaches for)
CRATE_ROLES: dict[str, tuple[str, ...]] = {
    "HTTP / network client": ("reqwest", "hyper", "ureq", "curl", "isahc", "attohttpc", "surf", "minreq", "http_req",
                              "awc", "tungstenite", "tokio-tungstenite", "websocket", "socket2"),
    "TLS": ("rustls", "native-tls", "openssl", "schannel", "tokio-rustls", "hyper-tls", "hyper-rustls"),
    "encryption": ("aes", "aes-gcm", "aes-soft", "chacha20", "chacha20poly1305", "salsa20", "rc4", "rsa", "ring",
                   "x25519-dalek", "ed25519-dalek", "blowfish", "des", "cbc", "ctr", "xsalsa20poly1305", "orion",
                   "sodiumoxide", "magic-crypt", "libaes", "rust-crypto"),
    "string obfuscation": ("obfstr", "litcrypt", "litcrypt2", "cryptify", "obfuscate", "goldberg", "obfus", "xorstr"),
    "system reconnaissance": ("sysinfo", "whoami", "hostname", "machine-uid", "local-ip-address", "wmi", "systemstat",
                              "os_info", "if-addrs", "get_if_addrs", "mac_address", "netstat2", "public-ip"),
    "Windows API": ("winapi", "windows", "windows-sys", "ntapi", "windows-service", "winsafe", "windows-native"),
    "registry / persistence": ("winreg", "registry", "auto-launch", "windows-service"),
    "screen capture": ("screenshots", "scrap", "xcap", "captrs", "win-screenshot"),
    "keyboard / input capture": ("rdev", "device_query", "inputbot", "keylogger", "win-hotkey", "enigo"),
    "clipboard": ("clipboard", "arboard", "clipboard-win", "cli-clipboard"),
    "browser data": ("rusqlite", "sqlite", "chrome-cookie", "cookie_store", "dpapi", "winapi-dpapi"),
    "process injection / memory": ("dinvoke", "dinvoke_rs", "memexec", "pe-parser", "goblin", "process-memory",
                                   "sysinfo-process", "shellcode", "syscalls", "freshycalls", "rust-syscalls"),
    "chat / C2 channel": ("teloxide", "frankenstein", "telegram-bot", "serenity", "twilight-http", "discord",
                          "slack-morphism", "matrix-sdk", "tor", "arti-client", "libp2p"),
    "compression / archives": ("zip", "flate2", "tar", "lzma-rs", "brotli", "zstd", "sevenz-rust"),
    "walking the file system": ("walkdir", "jwalk", "glob", "ignore", "globwalk"),
    "async runtime": ("tokio", "async-std", "smol"),
}
_ROLE_OF = {c: r for r, cs in CRATE_ROLES.items() for c in cs}
# roles worth a finding (on their own, or together)
_RISKY = {"string obfuscation", "keyboard / input capture", "screen capture", "process injection / memory",
          "browser data", "chat / C2 channel"}


def _rustc_version(commit: str | None) -> str | None:
    if not commit:
        return None
    try:                                              # FLOSS's table (Apache-2.0), when installed
        from floss.language.rust.rust_version_database import rust_commit_hash
        return rust_commit_hash.get(commit)
    except Exception:  # noqa: BLE001
        return None


def analyze_bytes(data: bytes) -> dict[str, Any] | None:
    """The Rust build facts in ``data``, or None when nothing says it is Rust."""
    commits = sorted({m.decode() for m in _COMMIT.findall(data)})
    versions = sorted({m.decode() for m in _VERSION.findall(data)})
    crates: dict[str, set[str]] = {}
    homes: set[tuple[str, str]] = set()
    for m in _REGISTRY.finditer(data):
        name = m.group(1).decode("ascii", "replace")
        crates.setdefault(name, set()).add(m.group(2).decode("ascii", "replace"))
    git = sorted({f"{m.group(1).decode()}@{m.group(2).decode()}" for m in _GIT.finditer(data)})
    if not (commits or versions or crates or git):
        return None
    for m in _HOME.finditer(data):
        user = (m.group(2) or m.group(3) or m.group(4) or b"").decode("utf-8", "replace")
        if user and user.lower() not in ("public", "default", "all users", "runner", "runneradmin"):
            homes.add(("windows" if m.group(1) else "unix", user))
    project: set[str] = set()
    prev = 0
    for m in _RS_END.finditer(data):
        end = m.end()
        lo = max(prev, end - 300, data.rfind(b"\x00", 0, end) + 1)
        seg = data[lo:end]
        prev = end
        roots = [r.start() for r in _ROOT.finditer(seg)]
        cand = seg[roots[-1]:] if roots else None
        if cand is None or not _PATH_OK.match(cand):
            rel = _REL_TAIL.search(seg)
            cand = rel.group(1) if rel else None
        if cand and re.search(rb"[\\/]src[\\/]|^src[\\/]", cand):    # a crate's sources live in src/
            p = cand.decode("utf-8", "replace")
            if not _TOOLCHAIN.search("/" + p):
                project.add(p)
    roles: dict[str, list[str]] = {}
    for name in crates:
        role = _ROLE_OF.get(name) or _ROLE_OF.get(name.replace("_", "-"))
        if role:
            roles.setdefault(role, []).append(name)
    commit = commits[0] if commits else None
    version = _rustc_version(commit) or (versions[0] if versions else None)
    # the build machine's user and the project name (the folder above src/)
    projects = sorted({re.split(r"[\\/]src[\\/]", p)[0].replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
                       for p in project if re.search(r"[\\/]src[\\/]", p) and not p.startswith("src")} - {""})
    return {
        "rustc_commit": commit, "rustc_commits": commits, "rustc_version": version,
        "crates": [{"name": n, "versions": sorted(v), "role": _ROLE_OF.get(n) or _ROLE_OF.get(n.replace("_", "-"))}
                   for n, v in sorted(crates.items())],
        "git_dependencies": git,
        "build_users": sorted({u for _, u in homes}),
        "project_paths": sorted(project)[:200],
        "projects": projects,
        "roles": {r: sorted(cs) for r, cs in sorted(roles.items())},
    }


def analyze(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("rb") as f:
            data = f.read(MAX_BYTES)
    except OSError:
        return None
    return analyze_bytes(data)


def findings(info: dict[str, Any], loc: str, finding: Any, prefix: str = "pe") -> list[dict[str, Any]]:
    """Findings from the Rust build facts (``finding`` = the triage's ``_finding``; rules
    ``<prefix>_rust_…``: pe for Windows, native for ELF / Mach-O)."""
    out = []
    ver = info.get("rustc_version") or (info.get("rustc_commit") or "")[:12]
    n = len(info.get("crates") or [])
    out.append(finding(f"{prefix}_rust_binary", "info", f"Rust binary (rustc {ver or '?'}), {n} crate(s)", loc,
                       ", ".join(c["name"] for c in (info.get("crates") or [])[:20])))
    roles = info.get("roles") or {}
    risky = sorted(r for r in roles if r in _RISKY)
    if risky:
        out.append(finding(f"{prefix}_rust_crates_capabilities", "medium",
                           "Rust crates for " + ", ".join(risky), loc,
                           "; ".join(f"{r}: {', '.join(roles[r])}" for r in risky)))
    if "HTTP / network client" in roles and "encryption" in roles:
        out.append(finding(f"{prefix}_rust_crates_capabilities", "low", "Rust crates for an HTTP client and encryption",
                           loc, f"HTTP: {', '.join(roles['HTTP / network client'])}; encryption: "
                                f"{', '.join(roles['encryption'])}"))
    if "encryption" in roles and "walking the file system" in roles:
        out.append(finding(f"{prefix}_rust_crates_capabilities", "medium",
                           "Rust crates for encryption and walking the file system (the shape of a locker)", loc,
                           f"encryption: {', '.join(roles['encryption'])}; file system: "
                           f"{', '.join(roles['walking the file system'])}"))
    if info.get("build_users"):
        out.append(finding(f"{prefix}_rust_build_user", "info",
                           "Build machine user in the Rust source paths: " + ", ".join(info["build_users"]), loc,
                           "; ".join(info.get("projects") or []) or "(from the cargo registry path)"))
    return out
