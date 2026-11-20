"""MCP server for DocuTraceX (stdio, or HTTP for clients on other machines).

Exposes the analysed cases as **read-only** MCP tools, so an MCP client
(Claude Desktop, Claude Code or another) can investigate them in natural
language without going through the web app:

    python -m docutracex.mcp_server                                  # stdio (the client starts it)
    python -m docutracex.mcp_server --http                           # http://127.0.0.1:8001/mcp
    python -m docutracex.mcp_server --http --host 0.0.0.0 --port 8001  # reachable from other machines

Over HTTP (MCP "streamable HTTP") the endpoint is ``/mcp`` and every request
needs ``Authorization: Bearer <token>``: the token is generated on first use
(``config/mcp_token.txt``), shown in the app's AI -> MCP tab (where the admin
regenerates it) and printed by ``python -m docutracex.users mcp-token``. Bound
to a non-loopback address, the SDK's DNS-rebinding protection is turned off so
clients can reach it by IP or host name.

It reads the same ``cases/`` folder as the web app (``DOCUTRACEX_CASES_DIR``
overrides it). Tools (see ``ai_tools``): list_cases, case_summary,
get_findings, get_iocs, get_module, get_network_checks, search_case,
list_code_objects, list_functions, get_function, get_decrypted, get_nested_tree, get_ml, query_registry,
list_modules, get_c2, get_c2_raw, get_yara, list_yara_rules — none can modify a case or touch the network.
Nothing is clipped: every answer comes whole, in pages of ~40,000 characters (``offset`` / ``next_offset``).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from . import ai_tools
from .config import settings

if os.environ.get("DOCUTRACEX_CASES_DIR"):
    settings.cases_dir = Path(os.environ["DOCUTRACEX_CASES_DIR"])

NAME = "docutracex"
INSTRUCTIONS = ("Read-only access to DocuTraceX forensic cases (Office/PDF/RTF/email maldoc analysis). "
                "Start with list_cases, then case_summary / get_findings / get_iocs; use get_module for a tool's "
                "raw output and get_network_checks for URL/domain/IP checks. For binaries: list_code_objects → "
                "list_functions → get_function; get_decrypted for what was decrypted statically, "
                "get_nested_tree for the chain of stages, get_ml for scores and similar objects in other cases; "
                "query_registry for registry hives / .reg files (SQL, search, browse); get_c2 / get_c2_raw for C2 "
                "configurations and each extractor's raw output; get_yara / list_yara_rules for YARA. Nothing is "
                "cut: long answers come in pages — when next_offset is not null, call the same tool again with "
                "offset=next_offset until it is null.")


def build_server():
    try:  # mcp >= 2
        from mcp.server.mcpserver import MCPServer as Server
    except ImportError:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP as Server
    server = Server(NAME, instructions=INSTRUCTIONS)

    def call(fn, *a, **kw):  # noqa: ANN001, ANN002, ANN003, ANN202
        with ai_tools.paged():               # everything, in pages: never clipped, never capped
            return fn(*a, **kw)

    @server.tool()
    def list_cases() -> dict:
        # trace: gmzpt
        """List the analysed cases, newest first (id, file, detected type, state, counts)."""
        return call(ai_tools.list_cases)

    @server.tool()
    def case_summary(case_id: str) -> dict:
        """Summary of a case: file, detected type and match, hashes, counts, modules run and analysis steps."""
        return call(ai_tools.case_summary, case_id)

    @server.tool()
    def list_modules(case_id: str) -> dict:
        """Every result file of the case (module and size), the C2 runs and the number of code results."""
        return call(ai_tools.list_modules, case_id)

    @server.tool()
    def get_findings(case_id: str, severity: Optional[str] = None, source: Optional[str] = None,
                     mark: Optional[str] = None, contains: Optional[str] = None, offset: int = 0) -> dict:
        """Consolidated findings (severity, source tool, rule, detail, location, evidence, ATT&CK) with the
        analyst's mark. Sorted high → info. Paged: call again with offset=next_offset until it is null."""
        return call(ai_tools.get_findings, case_id, severity, source, mark, contains, None, offset)

    @server.tool()
    def get_iocs(case_id: str, type: Optional[str] = None, contains: Optional[str] = None, offset: int = 0) -> dict:
        """IOCs of a case (url, domain, ipv4, ipv6, hash_like) and where each was seen. Paged (next_offset)."""
        return call(ai_tools.get_iocs, case_id, type, contains, None, offset)

    @server.tool()
    def get_module(case_id: str, module: str, offset: int = 0) -> dict:
        """Raw JSON result of one module (any of list_modules: ooxml, oletools, pdf, email, script, nested,
        c2, yara, ml, netcheck…), complete, as text slices: call again with offset=next_offset until it is
        null and join the slices."""
        return call(ai_tools.get_module, case_id, module, None, offset)

    @server.tool()
    def get_network_checks(case_id: str, offset: int = 0) -> dict:
        """URL/domain/IP network checks of a case: redirects, forms, cloaking, brand, RDAP age, ASN, Tor…
        Paged (next_offset)."""
        return call(ai_tools.get_network_checks, case_id, offset)

    @server.tool()
    def search_case(case_id: str, q: str, offset: int = 0) -> dict:
        """Case-insensitive text search across every result of a case (findings, IOCs, module outputs):
        every hit, paged (next_offset)."""
        return call(ai_tools.search_case, case_id, q, None, offset)

    @server.tool()
    def list_code_objects(case_id: str) -> dict:
        """Binaries of the case analysed as code (native with Rizin + rz-ghidra, Go, .NET CIL) and the
        'object' id to use with list_functions / get_function."""
        return call(ai_tools.list_code_objects, case_id)

    @server.tool()
    def list_functions(case_id: str, object: str, category: Optional[str] = None, name: Optional[str] = None,
                       offset: int = 0) -> dict:
        """Functions (native / Go) or .NET methods of interest of one object, most interesting first, all of
        them, paged (next_offset)."""
        return call(ai_tools.list_functions, case_id, object, category, name, None, offset)

    @server.tool()
    def get_function(case_id: str, object: str, function: str, offset: int = 0) -> dict:
        """One function: callers, callees, strings, and its whole code (pseudocode when decompiled, then the
        disassembly) as text slices (next_offset); for .NET the framework calls, literals, static arrays and
        the strings it decrypts."""
        return call(ai_tools.get_function, case_id, object, function, 12000, offset)

    @server.tool()
    def get_decrypted(case_id: str, offset: int = 0) -> dict:
        """Everything decrypted or decoded statically in the case, with the routine used. Paged (next_offset)."""
        return call(ai_tools.get_decrypted, case_id, 80, offset)

    @server.tool()
    def get_nested_tree(case_id: str, offset: int = 0) -> dict:
        """Every extracted, unpacked, hidden and decrypted stage, flat (path › to › node, depth), with how
        each was obtained and its findings. Paged (next_offset)."""
        return call(ai_tools.get_nested_tree, case_id, 6, offset)

    @server.tool()
    def get_ml(case_id: str, offset: int = 0) -> dict:
        """ML scores, unusual-for-the-model flags, top features, family guess, similar objects in other cases,
        highest score of the chain. Paged (next_offset)."""
        return call(ai_tools.get_ml, case_id, offset)

    @server.tool()
    def get_c2(case_id: str, family: Optional[str] = None, offset: int = 0) -> dict:
        """C2 / implant configurations with every field (family, C2, normalized values, summary, YARA rule
        names, provenance, objects carrying the same config, mark), how each extractor did, packed objects,
        the family-YARA rule sets. Paged (next_offset)."""
        return call(ai_tools.get_c2, case_id, family, offset)

    @server.tool()
    def get_c2_raw(case_id: str, object: Optional[str] = None, run_id: Optional[str] = None, offset: int = 0) -> dict:
        """RAW records of a C2 run (the latest unless run_id). Without object: the objects and each extractor's
        status. With object (index, name or part of its path): every extractor's raw output, as text slices
        (next_offset)."""
        return call(ai_tools.get_c2_raw, case_id, object, run_id, offset)

    @server.tool()
    def get_yara(case_id: str, rule: Optional[str] = None, object: Optional[str] = None, offset: int = 0) -> dict:
        """YARA hits (rule × object): meta, tags, every matched string (offset, hex, text), the bytes around it,
        the rule's source and the analyst's mark. Paged (next_offset)."""
        return call(ai_tools.get_yara, case_id, rule, object, offset)

    @server.tool()
    def list_yara_rules(contains: Optional[str] = None, offset: int = 0) -> dict:
        """The compiled YARA ruleset (rules, source files, compile errors) and the C2 family rule sets
        (CAPE / ditekSHen). Paged (next_offset)."""
        return call(ai_tools.list_yara_rules, contains, offset)

    @server.tool()
    def query_registry(case_id: str, sql: Optional[str] = None, q: Optional[str] = None, key: Optional[str] = None,
                       src: int = 0, limit: int = 200) -> dict:
        """Registry hives / .reg of the case. No argument: sources and schema. sql: one read-only SELECT over
        sources, keys(src, path, parent, name, last_write…) and vals(src, "key", name, type, data, size, raw);
        q: text search; key (+ src): subkeys and values of that key."""
        return call(ai_tools.query_registry, case_id, sql, q, key, src, limit)

    return server


_LOOPBACK = ("127.0.0.1", "localhost", "::1")


class BearerToken:
    """ASGI wrapper: every HTTP request needs ``Authorization: Bearer <token>``
    (the token of ``config/mcp_token.txt``, read on each request so a token
    regenerated in the app works at once and the old one stops)."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") == "http":
            from . import users
            auth = ""
            for k, v in scope.get("headers") or []:
                if k == b"authorization":
                    auth = v.decode("latin-1")
            token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
            if not users.mcp_token_ok(token):
                body = b'{"error": "DocuTraceX MCP: missing or wrong token (Authorization: Bearer <token>; see AI -> MCP)"}'
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"www-authenticate", b'Bearer realm="docutracex-mcp"'),
                                        (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


def http_app(server, host: str = "127.0.0.1"):
    """The MCP streamable-HTTP app (endpoint ``/mcp``) behind the bearer token, on mcp 2.x or 1.x."""
    sec = None
    if host not in _LOOPBACK:                        # reachable by IP / name: no Host-header allow-list
        try:
            from mcp.server.transport_security import TransportSecuritySettings
            sec = TransportSecuritySettings(enable_dns_rebinding_protection=False)
        except Exception:  # noqa: BLE001  (older SDK without it: nothing to turn off)
            sec = None
    try:                                             # mcp >= 2: options are arguments
        kw = {"host": host}
        if sec is not None:
            kw["transport_security"] = sec
        app = server.streamable_http_app(**kw)
    except TypeError:                                # mcp 1.x: they live in the settings
        server.settings.host = host
        if sec is not None and hasattr(server.settings, "transport_security"):
            server.settings.transport_security = sec
        app = server.streamable_http_app()
    return BearerToken(app)


def run_http(server, host: str = "127.0.0.1", port: int = 8001) -> None:
    """Serve over MCP streamable HTTP (endpoint ``/mcp``); clients must send the token."""
    import uvicorn

    from . import users
    users.mcp_token()                                # created on first use
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print(f"DocuTraceX MCP over HTTP: http://{shown}:{port}/mcp\n"
          "Clients must send 'Authorization: Bearer <token>'. The token is in AI -> MCP (web app), in\n"
          "config/mcp_token.txt, or: python -m docutracex.users mcp-token", file=sys.stderr, flush=True)
    from .winloop import uvicorn_loop
    uvicorn.run(http_app(server, host), host=host, port=port, log_level="info", loop=uvicorn_loop())


def main(argv: list[str] | None = None) -> None:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m docutracex.mcp_server",
                                 description="DocuTraceX MCP server (read-only tools over the cases).")
    ap.add_argument("--http", action="store_true",
                    help="serve over HTTP (streamable HTTP, endpoint /mcp) instead of stdio")
    ap.add_argument("--host", default="127.0.0.1",
                    help="address to bind with --http (default 127.0.0.1; 0.0.0.0 = every interface)")
    ap.add_argument("--port", type=int, default=8001, help="port with --http (default 8001)")
    a = ap.parse_args(argv)
    server = build_server()
    if a.http:
        run_http(server, a.host, a.port)
    else:
        server.run()


if __name__ == "__main__":
    main()
