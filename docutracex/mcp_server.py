"""MCP server for DocuTraceX (stdio).

Exposes the analysed cases as **read-only** MCP tools, so an MCP client
(Claude Desktop, Claude Code or another) can investigate them in natural
language without going through the web app:

    python -m docutracex.mcp_server

It reads the same ``cases/`` folder as the web app (``DOCUTRACEX_CASES_DIR``
overrides it). Tools (see ``ai_tools``): list_cases, case_summary,
get_findings, get_iocs, get_module, get_network_checks, search_case — none
can modify a case or touch the network.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from . import ai_tools
from .config import settings

if os.environ.get("DOCUTRACEX_CASES_DIR"):
    settings.cases_dir = Path(os.environ["DOCUTRACEX_CASES_DIR"])

NAME = "docutracex"
INSTRUCTIONS = ("Read-only access to DocuTraceX forensic cases (Office/PDF/RTF/email maldoc analysis). "
                "Start with list_cases, then case_summary / get_findings / get_iocs; use get_module for a tool's "
                "raw output and get_network_checks for URL/domain/IP checks.")


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

    return server


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
