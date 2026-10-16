"""AI tab: read-only case tools, the OpenAI-compatible chat loop, the MCP server."""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from docutracex import ai, ai_tools, analyze, cases
from docutracex.config import settings

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    base = tmp_path_factory.mktemp("cases")
    with (ROOT / "samples" / "sample.rtf").open("rb") as fh:
        m = cases.create_case(fh, "pedido.rtf", cases_dir=base)
    analyze.analyze_case(base / m["analysis_id"])
    return base, m["analysis_id"]


@pytest.fixture(autouse=True)
def _cases_dir(case, monkeypatch):
    monkeypatch.setattr(settings, "cases_dir", case[0])


def test_case_tools_read_the_analysis(case) -> None:
    cid = case[1]
    assert ai_tools.list_cases()["cases"][0]["case_id"] == cid
    s = ai_tools.case_summary(cid)
    assert s["file"] == "pedido.rtf" and "rtf" in s["modules_run"]
    high = ai_tools.get_findings(cid, severity="high")
    assert high["findings"] and all(f["severity"] == "high" for f in high["findings"])
    assert any(f["rule"] == "equation_editor" for f in ai_tools.get_findings(cid, source="rtf")["findings"])
    assert all(f["mark"] == "unreviewed" for f in high["findings"])
    assert any(i["value"].startswith("http://198.51.100.23") for i in ai_tools.get_iocs(cid, type="url")["iocs"])
    mod = ai_tools.get_module(cid, "rtf", max_chars=2000)
    assert mod["truncated"] and mod["json"].startswith("{")
    assert "available" in ai_tools.get_module(cid, "pdf")
    assert ai_tools.search_case(cid, "Equation.3")["hits"]


# id: sJkzUVgDiA
def test_tools_refuse_bad_ids() -> None:
    assert "error" in ai_tools.run_tool("case_summary", {"case_id": "../../etc"})
    assert "error" in ai_tools.run_tool("case_summary", {"case_id": "nope"})
    assert "error" in ai_tools.run_tool("drop_everything", {})


class _FakeLLM(BaseHTTPRequestHandler):
    """OpenAI-compatible endpoint: first asks for a tool, then answers with what it got."""
    calls: list[dict] = []

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _FakeLLM.calls.append({"auth": self.headers.get("Authorization"), "x": self.headers.get("x-team"), "body": body})
        tool_msgs = [m for m in body["messages"] if m["role"] == "tool"]
        if not tool_msgs:
            msg = {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "type": "function", "function": {
                "name": "get_findings", "arguments": json.dumps({"severity": "high"})}}]}
        else:
            got = json.loads(tool_msgs[-1]["content"])
            msg = {"role": "assistant", "content": f"{got['total']} high findings, e.g. {got['findings'][0]['rule']}"}
        data = json.dumps({"model": body["model"], "choices": [{"message": msg}]}).encode()
        # gmzpt
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a) -> None:
        pass


@pytest.fixture()
def llm():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FakeLLM)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _FakeLLM.calls = []
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1"
    srv.shutdown()


def test_chat_runs_the_tool_loop(case, llm: str) -> None:
    res = ai.chat("¿Qué hallazgos graves hay?", {"base_url": llm, "model": "m1", "api_key": "sk-x",
                                                   "extra_headers": {"x-team": "dfir"}}, case_id=case[1])
    assert "high findings, e.g." in res["reply"] and res["model"] == "m1"
    assert res["tool_trace"][0]["tool"] == "get_findings" and res["tool_trace"][0]["args"]["case_id"] == case[1]
    first = _FakeLLM.calls[0]
    assert first["auth"] == "Bearer sk-x" and first["x"] == "dfir"
    assert {t["function"]["name"] for t in first["body"]["tools"]} == set(ai_tools.TOOLS)
    assert case[1] in first["body"]["messages"][0]["content"]


def test_chat_validates_config() -> None:
    with pytest.raises(ValueError):
        ai.chat("hola", {"base_url": "", "model": "m"})
    with pytest.raises(ValueError):
        ai.chat("hola", {"base_url": "http://x", "model": ""})


def test_mcp_server_exposes_the_same_read_only_tools(case) -> None:
    pytest.importorskip("mcp")
    from docutracex import mcp_server

    srv = mcp_server.build_server()
    names = {t.name for t in asyncio.run(srv.list_tools())}
    assert names == set(ai_tools.TOOLS)
    out = asyncio.run(srv.call_tool("case_summary", {"case_id": case[1]}))
    text = out.content[0].text if hasattr(out, "content") else out[0].text if isinstance(out, list) else str(out)
    assert "pedido.rtf" in text


def test_api_mcp_info_and_chat_errors(case, llm: str) -> None:
    from fastapi.testclient import TestClient

    from docutracex.app import create_app

    client = TestClient(create_app())
    info = client.get("/api/mcp/info").json()
    cfg = json.loads(info["claude_desktop"])["mcpServers"]["docutracex"]
    assert cfg["args"] == ["-m", "docutracex.mcp_server"] and cfg["env"]["DOCUTRACEX_CASES_DIR"] == str(case[0])
    assert "claude mcp add docutracex" in info["claude_code"] and len(info["tools"]) == len(ai_tools.TOOLS)
    assert client.post("/api/ai/chat", json={"message": "x", "base_url": "", "model": "m"}).status_code == 400
    r = client.post("/api/ai/chat", json={"message": "x", "base_url": llm, "model": "m", "case_id": case[1]})
    assert r.status_code == 200 and "high findings" in r.json()["reply"]
