"""Code analysis engine (Rizin + rz-ghidra): Go phases 3-4 and the native Code tab."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from docutracex import codeanalysis as ca
from docutracex.codeanalysis import case as code_case
from docutracex.codeanalysis import priority
from docutracex.golang import detect

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_samples as ms

CODE = ms.code_samples()
URL = ms.CODE_URL
needs_rizin = pytest.mark.skipif(not ca.available(), reason="Rizin + rz-ghidra not provisioned")


def test_priority_categories_and_reasons() -> None:
    fn = {"name": "main.beacon", "named": True, "size": 120, "loops": 1, "xor_ops": 3}
    pts, reasons, cats = priority.score(fn, ["net/http.(*Client).Do", "os/exec.(*Cmd).Run"], [URL], "go")
    assert {"network", "exec", "transform"} <= set(cats)
    assert pts >= 30 + 30 + 20 + 15
    assert any("URL" in r for r in reasons) and any("XOR" in r for r in reasons)
    _p, _r, ncats = priority.score({"name": "fcn.1"}, ["imp.KERNEL32.dll_VirtualAlloc", "imp.KERNEL32.dll_WriteProcessMemory"], [], "native")
    assert "process" in ncats
    # a huge init table gets no size bonus
    assert priority.score({"name": "x", "size": 160000}, [], [], "go")[0] == 0


def test_readable_callee_names() -> None:
    assert ca._readable("sym.imp.KERNEL32.dll_VirtualAlloc") == "imp.KERNEL32.dll_VirtualAlloc"
    assert ca._readable("sym.main.foo") == "main.foo"
    assert ca._readable("fcn.00401000") == "fcn.00401000"


def test_go_names_from_the_own_pclntab_parser() -> None:
    data = CODE["go/sample_go_code.exe"]
    r = detect.identify(data)
    assert r["state"] in ("Confirmed", "Likely")
    names = code_case.go_names(data, r)
    by = {n["name"]: n for n in names}
    assert {"main.main", "main.decryptConfig", "main.beacon", "net/http.(*Client).Do"} <= set(by)
    assert by["main.main"]["start"] == 0x140001000 and by["main.main"]["user"]
    assert not by["net/http.(*Client).Do"]["user"]


def test_dotnet_is_left_to_its_own_analysis() -> None:
    assert code_case.is_dotnet(ms.agenttesla_exe())
    assert not code_case.is_dotnet(CODE["code/sample_code_loader.exe"])


def test_result_ids_are_validated(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        code_case.result_file(tmp_path, "../../etc", "go")
    with pytest.raises(ValueError):
        code_case.result_file(tmp_path, "a" * 64, "python")


@needs_rizin
def test_native_engine(tmp_path: Path) -> None:
    p = tmp_path / "loader.exe"
    p.write_bytes(CODE["code/sample_code_loader.exe"])
    out = tmp_path / "code.json"
    s = ca.analyze(p, mode="native", names=None, out_file=out, lock_path=tmp_path / "lock")
    assert s["status"] == "ok" and s["functions_analyzed"] == 3 and s["decompiled"] == 3
    full = json.loads(out.read_text())
    top = full["functions"][0]
    assert "network" in top["categories"] and any(st["value"] == URL for st in top["strings"])
    dec = next(f for f in full["functions"] if f.get("xor_keys"))
    assert dec["loops"] >= 1 and "transform" in dec["categories"]
    entry = next(f for f in full["functions"] if f["name"] == "entry0")
    assert len(entry["calls"]) == 2
    assert all(f["callers"] == [entry["addr"]] for f in full["functions"] if f is not entry)
    code = full["decompiled"][str(top["addr"])]["code"]
    assert "InternetOpenUrlA" in code and URL in code
    api = {a["name"]: a for a in full["apis"]}
    assert api["InternetOpenUrlA"]["used_by"] == [top["name"]] and "network" in api["InternetOpenUrlA"]["categories"]


@needs_rizin
def test_go_engine_restores_names(tmp_path: Path) -> None:
    data = CODE["go/sample_go_code.exe"]
    p = tmp_path / "agent.exe"
    p.write_bytes(data)
    names = code_case.go_names(data, detect.identify(data))
    out = tmp_path / "go.json"
    s = ca.analyze(p, mode="go", names=names, out_file=out, lock_path=tmp_path / "lock")
    assert s["status"] == "ok" and s["top"][0]["name"] == "main.beacon"
    full = json.loads(out.read_text())
    by = {f["name"]: f for f in full["functions"]}
    assert by["main.main"]["callee_names"] == ["main.decryptConfig", "runtime.newproc", "runtime.deferreturn"]
    assert {"entry", "goroutine", "defer"} <= set(by["main.main"]["traits"])
    assert by["main.main"]["spawns"] == [by["main.main.func1"]["addr"]]          # go func1()
    assert "closure" in by["main.main.func1"]["traits"]
    assert by["main.beacon"]["strings"][0]["value"] == URL                # Go string: pointer + length
    assert "net/http.(*Client).Do" in full["decompiled"][str(by["main.beacon"]["addr"])]["code"]
    one = ca.decompile_one(p, by["main.decryptConfig"]["addr"], mode="go", names=names, lock_path=tmp_path / "lock")
    assert one["status"] == "ok" and "0xa5" in one["code"] and one["ops"]

    g = code_case.graph(full)
    kinds = {(e["from"], e["to"]): e["kind"] for e in g["edges"]}
    assert kinds[(by["main.main"]["addr"], by["main.main.func1"]["addr"])] == "goroutine"
    assert g["roots"][0] == by["main.main"]["addr"]
    path = next(p["path"] for p in g["paths"] if p["target"] == "ext:net/http.(*Client).Do")
    assert path == [by["main.main"]["addr"], by["main.main.func1"]["addr"], by["main.beacon"]["addr"],
                    "ext:net/http.(*Client).Do"]
    cfg = ca.cfg_one(p, by["main.decryptConfig"]["addr"], mode="go", names=names, lock_path=tmp_path / "lock")
    assert cfg["status"] == "ok" and len(cfg["blocks"]) == 3 and cfg["loops"] == 1
    assert {e["kind"] for e in cfg["edges"]} >= {"jump", "fail"}


@needs_rizin
def test_case_pipeline_go_and_native(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from docutracex import analyze, cases
    from docutracex.app import create_app
    from docutracex.config import settings

    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    monkeypatch.setattr(settings, "goresym_executable", lambda: None)
    client = TestClient(create_app())

    m = cases.create_case(io.BytesIO(CODE["go/sample_go_code.exe"]), "factura.exe", cases_dir=tmp_path)
    cid = m["analysis_id"]
    analyze.analyze_case(tmp_path / cid)
    comp = client.get(f"/api/cases/{cid}/components").json()
    obj = comp["modules"]["golang"]["objects"][0]
    assert "_pcln" not in obj["result"]
    c = obj["code"]
    assert c["status"] == "ok" and c["mode"] == "go" and c["functions_total"] >= 4
    assert "code" not in comp["modules"]                       # Go objects are not repeated in the Code tab
    ov = client.get(f"/api/cases/{cid}/code/{c['sha256']}/go").json()
    assert ov["functions"][0]["name"] == "main.beacon" and ov["strings"][0]["value"] == URL
    addr = ov["functions"][0]["addr"]
    fv = client.get(f"/api/cases/{cid}/code/{c['sha256']}/go/fn/{addr}").json()
    assert fv["decompiled"]["status"] == "ok" and fv["callers"][0]["name"] == "main.main.func1" and fv["ops"]
    dv = client.post(f"/api/cases/{cid}/code/{c['sha256']}/go/fn/{addr}/decompile").json()
    assert dv["decompiled"]["on_demand"] is True
    assert obj["types"]["with_methods"] == 3                       # main.Config, http.Client, cipher.gcm
    ty = client.get(f"/api/cases/{cid}/golang/{c['sha256']}/types").json()
    cfgt = next(t for t in ty["types"] if t["name"] == "main.Config")
    assert cfgt["methods"][0]["method"] == "load" and cfgt["source"] == "method names"
    assert client.get(f"/api/cases/{cid}/golang/{'0' * 64}/types").status_code == 404
    g = client.get(f"/api/cases/{cid}/code/{c['sha256']}/go/graph").json()
    assert any(e["kind"] == "goroutine" for e in g["edges"]) and g["paths"]
    cf = client.get(f"/api/cases/{cid}/code/{c['sha256']}/go/fn/{addr}/cfg").json()
    assert cf["status"] == "ok" and cf["blocks"]
    assert client.get(f"/api/cases/{cid}/code/{c['sha256']}/go/fn/{addr}/cfg").json() == cf     # cached
    assert client.get(f"/api/cases/{cid}/code/{'0' * 64}/go").status_code == 404
    assert client.get(f"/api/cases/{cid}/code/xyz/go").status_code == 400

    m2 = cases.create_case(io.BytesIO(CODE["code/sample_code_loader.exe"]), "loader.exe", cases_dir=tmp_path)
    cid2 = m2["analysis_id"]
    analyze.analyze_case(tmp_path / cid2)
    comp2 = client.get(f"/api/cases/{cid2}/components").json()
    co = comp2["modules"]["code"]["objects"][0]
    assert co["original"] and co["code"]["status"] == "ok" and co["code"]["apis"] == 5
    ov2 = client.get(f"/api/cases/{cid2}/code/{co['sha256']}/native").json()
    assert ov2["apis"][0]["used_by"]


def test_diagnostics_has_rizin_check() -> None:
    from docutracex.deps import run_checks

    c = next(x for x in run_checks()["checks"] if x["name"] == "Rizin + rz-ghidra (code analysis)")
    assert c["status"] == "ok" or c["retry"] == "rizin"


# --- phase 6: resources, FLOSS per function, dependencies, IOCs ---------------------

def test_go_embed_certificates_and_compressed_data() -> None:
    from docutracex.codeanalysis import resources
    from docutracex.golang import binfmt
    data = CODE["go/sample_go_code.exe"]
    res = resources.scan(data, binfmt.parse(data), "go")
    files = {f["name"]: f for fs in res["embed"] for f in fs["files"]}
    assert set(files) == set(ms.CODE_EMBED)
    assert files["assets/config.json"]["data"] == ms.CODE_EMBED["assets/config.json"]
    assert data[files["assets/config.json"]["offset"]:].startswith(b'{"c2"')
    cert = res["certificates"][0]
    assert cert["type"] == "pem" and "CN=cdn-update.example.net" in cert["subject"] and cert["self_signed"]
    assert [c["type"] for c in res["compressed"]] == ["gzip"] and b"INV-2026-0413" in res["compressed"][0]["data"]
    # nothing in the native sample, and random bytes do not make an embed.FS
    plain = CODE["code/sample_code_loader.exe"]
    assert resources.scan(plain, binfmt.parse(plain), "go") == {"embed": [], "certificates": [], "compressed": []}


def test_go_dependencies_declared_vs_code() -> None:
    from docutracex.codeanalysis import resources
    bi = {"path": "example.com/agent", "deps": [{"path": "github.com/kbinani/screenshot"}, {"path": "golang.org/x/sys"}]}
    names = ["main.main", "example.com/agent/net.(*C).Send", "golang.org/x/sys/windows.VirtualAlloc",
             "github.com/evil/copied.Run", "runtime.main", "net/http.(*Client).Do"]
    d = resources.go_dependencies(bi, names)
    assert d["with_code"] == ["golang.org/x/sys"] and d["without_code"] == ["github.com/kbinani/screenshot"]
    assert d["undeclared"] == [("github.com/evil/copied", 1)]
    assert resources.go_package("github.com/a/b/pkg.(*T).M") == "github.com/a/b/pkg"


def test_floss_strings_land_on_their_function() -> None:
    full = {"functions": [{"addr": 0x1000, "size": 0x40, "name": "main.decode"},
                          {"addr": 0x2000, "size": 0x10, "name": "main.other"}]}
    n = code_case.attach_floss(full, [{"kind": "stack", "string": "cmd.exe /c whoami", "function": 0x1010},
                                      {"kind": "decoded", "string": "orphan", "function": 0x9000}])
    assert n == 1 and full["functions"][0]["floss"] == [{"value": "cmd.exe /c whoami", "kind": "stack"}]
    assert {s["function"] for s in full["floss"]} == {"main.decode", ""}


@needs_rizin
def test_case_pipeline_resources_and_iocs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze, cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json

    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    monkeypatch.setattr(settings, "goresym_executable", lambda: None)
    m = cases.create_case(io.BytesIO(CODE["go/sample_go_code.exe"]), "factura.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    paths = CasePaths(m["analysis_id"], cases_dir=tmp_path)
    g = read_json(paths.subresult("golang"))
    assert "_children" not in g
    o = g["objects"][0]
    assert o["code"]["resources"]["embed_files"] == 2 and o["code"]["resources"]["certificates"] == 1
    tree = read_json(paths.subresult("nested"))["tree"]
    kids = {n["decrypted_from"]: n for n in tree}
    assert "go:embed assets/config.json in factura.exe" in kids
    assert all(n.get("source") == "code-resources" for n in tree)
    iocs = {i["value"] for i in read_json(paths.subresult("iocs"))["iocs"]}
    assert {URL, "203.0.113.47", "cdn-update.example.net"} <= iocs
    full = code_case.load(paths.root, o["sha256"], "go")
    assert full["dependencies"]["without_code"] == ["github.com/kbinani/screenshot", "golang.org/x/sys"]
    assert all("data" not in f for fs in full["resources"]["embed"] for f in fs["files"])


def test_clean_child_detection() -> None:
    from docutracex import golang
    assert golang.clean_child([{"filename": "big.exe", "stored_path": "extracted/x/big.exe", "recipe": ["debloat", "padded"]}]) == "big.exe"
    assert golang.clean_child([{"filename": "u.exe", "stored_path": "e/u.exe", "source": "unpack"}]) == "u.exe"
    assert golang.clean_child([{"filename": "a.txt", "stored_path": "e/a.txt", "recipe": ["zip"]}]) == ""


@needs_rizin
def test_padded_original_is_analysed_in_its_clean_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from docutracex import analyze, cases
    from docutracex.config import settings
    from docutracex.storage import CasePaths, read_json

    pytest.importorskip("debloat")
    monkeypatch.setattr(settings, "cases_dir", tmp_path)
    m = cases.create_case(io.BytesIO(ms.bloated_exe()), "factura.exe", cases_dir=tmp_path)
    analyze.analyze_case(tmp_path / m["analysis_id"])
    code = read_json(CasePaths(m["analysis_id"], cases_dir=tmp_path).subresult("code"))
    orig = next(o for o in code["objects"] if o["original"])
    assert orig["code"]["status"] == "skipped" and orig["code"]["clean_child"]
    child = next(o for o in code["objects"] if not o["original"])
    assert child["code"]["status"] in ("ok", "partial")


# --- phase 8: cryptography -----------------------------------------------------------

def test_crypto_constants_and_custom_base64() -> None:
    from docutracex.codeanalysis import crypto
    from docutracex.golang import binfmt
    data = CODE["go/sample_go_code.exe"]
    names = {c["constant"] for c in crypto.scan_constants(data, binfmt.parse(data))}
    assert {"AES S-box", "SHA-256 round constants"} <= names
    alpha = b"ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
    blob = b"MZ" + b"\x00" * 100 + alpha + b"\x00" * 10
    hits = crypto.scan_constants(blob, binfmt.parse(blob))
    assert [h["algorithm"] for h in hits] == ["Base64 (custom alphabet)"]
    std = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    assert crypto.scan_constants(b"\x00" + std + b"\x00", binfmt.parse(b"\x00")) == []


def test_crypto_static_decryption_primitives() -> None:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from docutracex.codeanalysis import crypto
    key, iv = bytes(range(32)), bytes(range(16))
    pt, method = crypto._try_decrypt("AES-GCM", ms.CODE_GCM_KEY, ms.CODE_GCM_NONCE, ms.CODE_SEALED)
    assert pt == ms.CODE_CONFIG and "authenticated" in method
    assert crypto._try_decrypt("AES-GCM", key, ms.CODE_GCM_NONCE, ms.CODE_SEALED) is None      # wrong key: tag fails
    p = padding.PKCS7(128).padder()
    msg = b"powershell -enc ... invoice payload"
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = e.update(p.update(msg) + p.finalize()) + e.finalize()
    assert crypto._try_decrypt("AES-CBC", key, iv, ct)[0] == msg
    assert crypto._try_decrypt("RC4", b"secretkey", None, crypto._rc4(b"secretkey", msg))[0] == msg


@needs_rizin
def test_crypto_on_the_go_sample(tmp_path: Path) -> None:
    from docutracex.codeanalysis import _Reader, crypto
    from docutracex.golang import binfmt
    data = CODE["go/sample_go_code.exe"]
    p = tmp_path / "agent.exe"
    p.write_bytes(data)
    names = code_case.go_names(data, detect.identify(data))
    out = tmp_path / "go.json"
    ca.analyze(p, mode="go", names=names, out_file=out, lock_path=tmp_path / "lock")
    full = json.loads(out.read_text())
    r = crypto.analyze(full, data, binfmt.parse(data), _Reader(data), names, "go")
    algos = {a["algorithm"] for a in r["algorithms"]}
    assert {"AES", "SHA-256", "block-cipher modes"} <= algos
    fn = next(f for f in r["functions"] if f["name"] == "main.openConfig")
    assert fn["roles"] == ["decrypt"]
    assert {k["size"] for k in r["keys"] if k["function"] == "main.openConfig"} == {32, 12}
    plain = {x["method"].split(" ")[0]: x for x in r["plaintexts"]}
    assert plain["AES-GCM"]["plaintext"] == ms.CODE_CONFIG and plain["AES-GCM"]["status"] == "reconstructed"
    assert plain["XOR"]["plaintext"] == ms.CODE_SECRET and plain["XOR"]["function"] == "main.decryptConfig"
