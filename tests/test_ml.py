"""Machine Learning tab: EMBER2024 LightGBM classifier (EMBER feature v3)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_js_techniques import _analyze, _ms, client  # noqa: E402,F401

_DEPS = all(importlib.util.find_spec(m) for m in ("lightgbm", "mmh3", "signify"))
pytestmark = pytest.mark.skipif(not _DEPS, reason="lightgbm / mmh3 / signify not installed")

from docutracex.config import settings  # noqa: E402

_REAL = (settings.tools_dir / "ember" / "EMBER2024_Win64.model").is_file()


def _fake_models(d: Path, nfeat: int = 2568) -> Path:
    import lightgbm as lgb
    import numpy as np
    rng = np.random.default_rng(0)
    X = rng.random((300, nfeat)).astype(np.float32)
    y = (X[:, 1] + X[:, 2] > 1).astype(int)
    b = lgb.train({"objective": "binary", "verbosity": -1, "num_leaves": 8}, lgb.Dataset(X, y), 10)
    d.mkdir(parents=True, exist_ok=True)
    for t in ("Win32", "Win64", "Dot_Net", "PDF", "ELF", "all"):
        b.save_model(str(d / f"EMBER2024_{t}.model"))
    return d


def test_feature_layout_and_hashed_names() -> None:
    from docutracex.ml import ember_features as ef
    from docutracex.ml import ember_ml
    ex = ef.PEFeatureExtractor()
    assert ex.dim == ef.PE_DIM == 2568
    assert sum(f.dim for f in ex.features[:4]) == ef.NON_PE_DIM
    names = ember_ml.feature_names(ex)
    assert len(names) == ex.dim
    # every non-zero hashed bucket of a real PE is resolved to this file's own items
    import numpy as np
    raw = ex.raw_features(_ms().lief_helper_dll())
    vec = ex.process_raw_features(raw)
    res = ember_ml._resolve_hashed(raw)
    hashed = {names[i][1] for i in np.nonzero(vec)[0]
              if names[i][0] in ("imports", "exports", "sections", "rich header") and "#" in names[i][1]}
    assert hashed <= set(res)


def test_classify_formats_and_mismatch(tmp_path: Path) -> None:
    from docutracex.ml import ember_ml
    mdir = _fake_models(tmp_path / "m")
    files = {"a.dll": _ms().lief_helper_dll(), "b.pdf": b"%PDF-1.4\n%%EOF\n", "c.txt": b"hello"}
    paths = []
    for n, b in files.items():
        (tmp_path / n).write_bytes(b)
        paths.append(str(tmp_path / n))
    r = {Path(x["path"]).name: x for x in ember_ml._classify(paths, str(mdir))}
    assert r["a.dll"]["status"] == "ok" and r["a.dll"]["model"] == "EMBER2024_Win64"
    assert len(r["a.dll"]["top_features"]) <= ember_ml.TOP_N and r["a.dll"]["blocks"]
    assert r["b.pdf"]["model"] == "EMBER2024_PDF"
    assert r["c.txt"]["status"] == "unsupported"
    bad = _fake_models(tmp_path / "bad", nfeat=100)
    x = ember_ml._classify([paths[0]], str(bad))[0]
    assert x["status"] == "error" and "feature mismatch" in x["detail"]


def test_triage_only_like_yara() -> None:
    from docutracex import marks
    from docutracex.ml import ember_ml
    f = ember_ml.finding_for({"status": "ok", "score": 0.99, "threshold": 0.5, "model": "EMBER2024_Win64",
                              "format": "PE (Win64)", "label": "x.exe", "top_features": []})
    assert f["severity"] == "medium" and "above" in f["detail"]
    assert marks.is_triage_only({"source": "ml", "rule": f["rule"]})
    assert ember_ml.finding_for({"status": "error"}) is None


@pytest.mark.skipif(not _REAL, reason="EMBER2024 models not provisioned (tools/ember)")
def test_real_models_on_samples_end_to_end(client) -> None:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("factura_visor.exe", _ms().packed_pe_exe())
        z.writestr("invoice_helper.dll", _ms().lief_helper_dll())
    cid, res = _analyze(client, "factura_pack.zip", buf.getvalue())
    ml = json.loads((res / "ml.json").read_text())
    by = {i["label"].split(" › ")[-1]: i for i in ml["items"]}
    assert by["factura_visor.exe"]["verdict"] == "above threshold"
    assert by["invoice_helper.dll"]["verdict"] == "below threshold"
    assert by["factura_visor.exe"]["calibrated"] and by["factura_visor.exe"]["metrics"]["tpr_at_fpr_0.01"] > 0.9
    comps = client.get(f"/api/cases/{cid}/components").json()
    assert len(comps["ml_findings"]) == 2 and not [f for f in comps["findings"] if f["source"] == "ml"]
    fid = by["factura_visor.exe"]["finding_id"]
    r = client.put(f"/api/cases/{cid}/marks/{fid}", json={"state": "true_positive"})
    assert r.status_code < 400
    comps = client.get(f"/api/cases/{cid}/components").json()
    assert [f["id"] for f in comps["findings"] if f["source"] == "ml"] == [fid]


def test_installer_pins_every_model() -> None:
    data = json.loads((Path(__file__).resolve().parent.parent / "docutracex" / "ml" / "ember_thresholds.json").read_text())
    for name, meta in data["models"].items():
        assert len(meta["sha256"]) == 64 and meta["num_feature"] == 2568, name
        assert 0 < meta["threshold_fpr_0.01"] < 1


def test_family_download_verifies_hash(tmp_path: Path, monkeypatch) -> None:
    import hashlib
    import io
    import time

    from docutracex.ml import family_download as fd
    data = b"tree\nversion=v4\n" + b"x" * 5000
    monkeypatch.setattr(fd, "target", lambda: tmp_path / "EMBER2024_family.model")

    class R(io.BytesIO):
        headers = {"Content-Length": str(len(data))}
        def __enter__(self): return self
        def __exit__(self, *a): return False

    class Opener:
        def open(self, req, timeout=0): return R(data)

    monkeypatch.setattr(fd.urllib.request, "build_opener", lambda *a: Opener())
    for sha, want in (("0" * 64, "error"), (hashlib.sha256(data).hexdigest(), "done")):
        monkeypatch.setattr(fd, "_meta", lambda sha=sha: {"sha256": sha, "size": len(data)})
        fd._state.clear(); fd._state["state"] = "idle"
        fd.start()
        for _ in range(100):
            if fd.status()["state"] != "downloading":
                break
            time.sleep(0.02)
        assert fd.status()["state"] == want
    assert (tmp_path / "EMBER2024_family.model").read_bytes() == data
    assert not (tmp_path / "EMBER2024_family.model.part").exists()


def test_hasher_matches_sklearn_exactly() -> None:
    sk = pytest.importorskip("sklearn.feature_extraction")
    import random

    import numpy as np

    from docutracex.ml.hashing import FeatureHasher
    rnd = random.Random(7)
    alph = "abcXYZ09:._-ñ€\x00"
    for _ in range(500):
        n = rnd.choice([10, 32, 50, 128, 256, 1024])
        it = rnd.choice(["string", "pair"])
        alt = rnd.choice([True, False])
        word = lambda k: "".join(rnd.choice(alph) for _ in range(rnd.randint(0, k)))  # noqa: E731
        x = ([word(12) for _ in range(rnd.randint(1, 30))] if it == "string" else
             [(word(8), rnd.choice([0, 1, 2.5, -3, rnd.random() * 1e6, "v1", 7])) for _ in range(rnd.randint(1, 30))])
        a = sk.FeatureHasher(n, input_type=it, alternate_sign=alt).transform([x]).toarray()[0]
        b = FeatureHasher(n, input_type=it, alternate_sign=alt).transform([x]).toarray()[0]
        assert np.array_equal(a.astype(np.float32), b.astype(np.float32))


@pytest.mark.skipif(not (settings.tools_dir / "ember" / "EMBER2024_APK.model").is_file(), reason="APK model not provisioned")
def test_apk_is_classified(client) -> None:
    _, res = _analyze(client, "sample_invoice_viewer.apk", _ms().invoice_viewer_apk())
    items = json.loads((res / "ml.json").read_text())["items"]
    apk = next(i for i in items if i.get("file_type") == "APK")
    assert apk["status"] == "ok" and apk["model"] == "EMBER2024_APK"


def test_help_data_has_metrics_and_labels() -> None:
    from docutracex.ml import ember_ml
    h = ember_ml.help_data()
    assert {"Win32", "Win64", "Dot_Net", "PDF", "ELF", "APK"} <= set(h["models"])
    assert 0.8 < h["models"]["Win32"]["tpr_at_fpr_0.01"] < 1
    assert "upx" in h["labels"]["packer"]["high"] and h["labels"]["family"]["high"][0] == "berbew"


def test_crlf_tag_model_loads_and_is_repaired(tmp_path: Path) -> None:
    """Tag boosters converted on Windows by older installs have CRLF line ends,
    which break LightGBM's tree_sizes offsets ("expect a tree here")."""
    import lightgbm as lgb
    import numpy as np

    from docutracex.ml import ember_ml

    X = np.random.default_rng(0).random((200, 4))
    y = (X[:, 0] > 0.5).astype(int)
    text = lgb.train({"objective": "binary", "verbose": -1}, lgb.Dataset(X, y), num_boost_round=3).model_to_string()
    f = tmp_path / "tags" / "packer" / "000.txt"
    f.parent.mkdir(parents=True)
    f.write_bytes(text.replace("\n", "\r\n").encode())
    extra = ember_ml._load_extra(tmp_path, lgb)
    assert len(extra["packer"]) == 1 and extra["packer"][0].num_trees() == 3
    assert b"\r\n" not in f.read_bytes()           # fixed on disk once
