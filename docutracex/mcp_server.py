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
list_code_objects, list_functions, get_function, get_decrypted, get_nested_tree, get_ml, query_registry — none
can modify a case or touch the network.
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
                "query_registry for registry hives / .reg files (SQL, search, browse).")


def build_server():
    try:  # mcp >= 2
        from mcp.server.mcpserver import MCPServer as Server
    except ImportError:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP as Server
    server = Server(NAME, instructions=INSTRUCTIONS)

    @server.tool()
    def list_cases() -> dict:
        # trace: gmzpt
        """List the analysed cases, newest first (id, file, detected type, state, counts)."""
        return ai_tools.list_cases()

    @server.tool()
    def case_summary(case_id: str) -> dict:
        """Summary of a case: file, detected type and match, hashes, counts, modules run and analysis steps."""
        return ai_tools.case_summary(case_id)

    @server.tool()
    def get_findings(case_id: str, severity: Optional[str] = None, source: Optional[str] = None,
                     mark: Optional[str] = None, contains: Optional[str] = None, limit: int = 60) -> dict:
        """Consolidated findings (severity, source tool, rule, detail, location, evidence) with the analyst's
        mark (unreviewed / true_positive / false_positive / suspicious / informational). Sorted high → info."""
        return ai_tools.get_findings(case_id, severity, source, mark, contains, limit)

    @server.tool()
    def get_iocs(case_id: str, type: Optional[str] = None, contains: Optional[str] = None, limit: int = 100) -> dict:
        """IOCs of a case (url, domain, ipv4, ipv6, hash_like) and where each was seen."""
        return ai_tools.get_iocs(case_id, type, contains, limit)

    @server.tool()
    def get_module(case_id: str, module: str, max_chars: int = 20000) -> dict:
        """Raw JSON result of one module (ooxml, word, excel, oletools, vbatools, vipermonkey, officerules,
        pdf, pdftools, email, mailrules, javascript, rtf, nested, netcheck, yara…), trimmed."""
        return ai_tools.get_module(case_id, module, max_chars)

    @server.tool()
    def get_network_checks(case_id: str) -> dict:
        """URL/domain/IP network checks of a case: redirects, forms, cloaking, brand, RDAP age, ASN, Tor…"""
        return ai_tools.get_network_checks(case_id)

    @server.tool()
    def search_case(case_id: str, q: str, limit: int = 40) -> dict:
        """Case-insensitive text search across every result of a case (findings, IOCs, module outputs)."""
        return ai_tools.search_case(case_id, q, limit)

    @server.tool()
    def list_code_objects(case_id: str) -> dict:
        """Binaries of the case analysed as code (native with Rizin + rz-ghidra, Go, .NET CIL) and the
        'object' id to use with list_functions / get_function."""
        return ai_tools.list_code_objects(case_id)

    @server.tool()
    def list_functions(case_id: str, object: str, category: Optional[str] = None, name: Optional[str] = None,
                       limit: int = 40) -> dict:
        """Functions (native / Go) or .NET methods of interest of one object, most interesting first."""
        return ai_tools.list_functions(case_id, object, category, name, limit)

    @server.tool()
    def get_function(case_id: str, object: str, function: str, max_chars: int = 12000) -> dict:
        """One function: pseudocode (if decompiled), disassembly, callers, callees, strings; for .NET the
        framework calls, literals, static arrays and the strings it decrypts."""
        return ai_tools.get_function(case_id, object, function, max_chars)

    @server.tool()
    def get_decrypted(case_id: str, limit: int = 80) -> dict:
        """Everything decrypted or decoded statically in the case, with the routine used."""
        return ai_tools.get_decrypted(case_id, limit)

    @server.tool()
    def get_nested_tree(case_id: str, max_depth: int = 6) -> dict:
        """Tree of extracted, unpacked, hidden and decrypted stages, with how each was obtained."""
        return ai_tools.get_nested_tree(case_id, max_depth)

    @server.tool()
    def get_ml(case_id: str) -> dict:
        """ML scores, unusual-for-the-model flags, similar objects in other cases, highest score of the chain."""
        return ai_tools.get_ml(case_id)

    @server.tool()
    def query_registry(case_id: str, sql: Optional[str] = None, q: Optional[str] = None, key: Optional[str] = None,
                       src: int = 0, limit: int = 200) -> dict:
        """Registry hives / .reg of the case. No argument: sources and schema. sql: one read-only SELECT over
        sources, keys(src, path, parent, name, last_write…) and vals(src, "key", name, type, data, size, raw);
        q: text search; key (+ src): subkeys and values of that key."""
        return ai_tools.query_registry(case_id, sql, q, key, src, limit)

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
    uvicorn.run(http_app(server, host), host=host, port=port, log_level="info")


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
