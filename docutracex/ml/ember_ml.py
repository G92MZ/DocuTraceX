"""Machine Learning tab: EMBER2024 LightGBM detection models.

Static ML classification of PE (Win32 / Win64 / .NET), PDF and ELF files with
the benchmark models published with EMBER2024 (Joyce et al., KDD 2025; Apache
2.0). Features: EMBER feature version 3 (``ember_features``, vendored, exactly
the extractor the models were trained with). For each object it returns

- the model used and its **score** (0–1);
- a verdict only against a **calibrated threshold** (1% false-positive rate on
  the EMBER2024 test set of that file type, ``ember_thresholds.json``) — never
  a fixed 0.5; without a threshold the score is shown "uncalibrated";
- **why**: per-feature contributions (LightGBM's native TreeSHAP,
  ``pred_contrib=True``), summed per feature block and the top features with a
  readable name — hashed buckets are resolved back to this file's own imports,
  exports, section names… that fall in them.

It is a complementary indicator, not a verdict: on EMBER2024's challenge set
(malware no AV detected at first) the PE models' PR AUC drops to 0.47–0.66.
The family / behaviour models are not used: their index → name mapping was
never published.

Runs in a child process with a time limit (``python -m docutracex.ml.ember_ml
FILE…``) so a slow parse or a crash costs only this step. Nothing is executed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

MODEL_TYPES = ("Win32", "Win64", "Dot_Net", "PDF", "ELF", "PE", "all")
THRESHOLDS_FILE = Path(__file__).with_name("ember_thresholds.json")
MAX_BYTES = 256 * 1024 * 1024
TOP_N = 10

_FORMAT_LABEL = {"Win32": "PE (Win32)", "Win64": "PE (Win64)", "Dot_Net": ".NET", "PDF": "PDF", "ELF": "ELF"}


def models_dir() -> Path:
    from ..config import settings
    return settings.tools_dir / "ember"


def status() -> dict[str, Any]:
    import importlib.util
    d = models_dir()
    have = [t for t in MODEL_TYPES if (d / f"EMBER2024_{t}.model").is_file()]
    deps = all(importlib.util.find_spec(m) is not None for m in ("lightgbm", "sklearn", "signify", "pefile"))
    return {"models": have, "dir": str(d), "deps": deps,
            "available": deps and bool(have), "calibrated": THRESHOLDS_FILE.is_file()}


def file_type(head: bytes, path: Path) -> str | None:
    """EMBER model family for a file: Win32 / Win64 / Dot_Net / PDF / ELF, or None."""
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:5] == b"%PDF-" or b"%PDF-" in head[:1024]:
        return "PDF"
    if head[:2] != b"MZ":
        return None
    try:
        import pefile
        pe = pefile.PE(str(path), fast_load=True)
        clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14] if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14 else None
        if clr is not None and clr.VirtualAddress and clr.Size:
            return "Dot_Net"
        return "Win64" if pe.FILE_HEADER.Machine in (0x8664, 0xAA64) else "Win32"
    except Exception:  # noqa: BLE001 - unparseable MZ: still a PE for EMBER
        return "Win32"


# --- feature names (readable) --------------------------------------------------

def feature_names(ex: Any) -> list[tuple[str, str]]:
    """(block, name) for every index of the EMBER v3 vector."""
    out: list[tuple[str, str]] = []
    for fe in ex.features:
        n = fe.name
        if n == "general":
            out += [("general", x) for x in ("file size", "file entropy", "is PE",
                                              "first byte", "second byte", "third byte", "fourth byte")]
        elif n == "histogram":
            out += [("byte histogram", f"byte 0x{i:02x} frequency") for i in range(256)]
        elif n == "byteentropy":
            out += [("byte entropy", f"entropy×byte bin {i // 16},{i % 16}") for i in range(256)]
        elif n == "strings":
            pats = sorted(fe._regexes)
            out += [("strings", x) for x in ("number of strings", "average string length", "printable chars")]
            out += [("strings", f"printable char {chr(32 + i)!r} share") for i in range(96)]
            out += [("strings", "string entropy")]
            out += [("strings", f"strings matching '{p}'") for p in pats]
        elif n == "header":
            base = ["COFF timestamp", "number of sections", "number of symbols", "size of optional header",
                    "pointer to symbol table", "machine", "subsystem", "image version (major)",
                    "image version (minor)", "linker version (major)", "linker version (minor)",
                    "OS version (major)", "OS version (minor)", "subsystem version (major)",
                    "subsystem version (minor)", "size of code", "size of headers", "size of image",
                    "size of initialized data", "size of uninitialized data", "stack reserve",
                    "stack commit", "heap reserve", "heap commit", "entry point address", "base of code",
                    "image base", "section alignment", "header checksum", "number of RVAs and sizes"]
            out += [("header", x) for x in base]
            out += [("header", f"characteristic {c}") for c in fe._image_characteristics]
            out += [("header", f"DLL characteristic {c}") for c in fe._dll_characteristics]
            out += [("header", f"DOS header {m}") for m in fe._dos_members]
        elif n == "section":
            gen = ["number of sections", "zero-size sections", "unnamed sections", "R+X sections",
                   "writable sections", "max section/overlay entropy", "min section/overlay entropy",
                   "max size ratio", "min size ratio", "max virtual size ratio", "min virtual size ratio"]
            out += [("sections", x) for x in gen]
            for what, k in (("section size", 50), ("section virtual size", 50), ("section entropy", 50),
                            ("section characteristic", 50), ("entry-point section", 10)):
                out += [("sections", f"{what} #{i}") for i in range(k)]
            out += [("sections", x) for x in ("overlay size", "overlay size ratio", "overlay entropy")]
        elif n == "imports":
            out += [("imports", "number of imported functions"), ("imports", "number of imported DLLs")]
            out += [("imports", f"imported DLL #{i}") for i in range(256)]
            out += [("imports", f"imported function #{i}") for i in range(1024)]
        elif n == "exports":
            out += [("exports", "export table size")] + [("exports", f"export #{i}") for i in range(128)]
        elif n == "datadirectories":
            for d in fe._name_order:
                out += [("data directories", f"{d} size"), ("data directories", f"{d} address")]
            out += [("data directories", "has relocations"), ("data directories", "has dynamic relocations")]
        elif n == "richheader":
            out += [("rich header", "number of entries")] + [("rich header", f"tool #{i}") for i in range(32)]
        elif n == "authenticode":
            out += [("authenticode", x) for x in ("number of signatures", "self-signed cert",
                                                   "empty program name", "no countersigner", "parse error",
                                                   "chain depth", "latest signing time",
                                                   "signing time − compile time")]
        elif n == "pefilewarnings":
            ws = sorted(fe.warning_ids, key=fe.warning_ids.get)
            out += [("parse warnings", f"pefile warning: {w[:80]}") for w in ws]
            out += [("parse warnings", "number of pefile warnings")]
        else:
            out += [(n, f"{n} #{i}") for i in range(fe.dim)]
    return out


def _bucket(s: str, n: int) -> int:
    from sklearn.utils import murmurhash3_32
    return abs(murmurhash3_32(s, seed=0)) % n


def _resolve_hashed(raw: dict[str, Any]) -> dict[str, list[str]]:
    """'imports: imported function #417' → the file's own imports in that bucket."""
    res: dict[str, list[str]] = {}

    def add(key: str, label: str) -> None:
        res.setdefault(key, [])
        if label not in res[key] and len(res[key]) < 6:
            res[key].append(label)

    imps = raw.get("imports") or {}
    for lib, funcs in imps.items():
        add(f"imported DLL #{_bucket(lib.lower(), 256)}", lib.lower())
        for e in funcs:
            add(f"imported function #{_bucket(lib.lower() + ':' + e, 1024)}", f"{lib.lower()}:{e}")
    for e in raw.get("exports") or []:
        add(f"export #{_bucket(e, 128)}", e)
    sec = raw.get("section") or {}
    for s in sec.get("sections") or []:
        nm = s.get("name", "")
        for what in ("section size", "section virtual size", "section entropy"):
            add(f"{what} #{_bucket(nm, 50)}", nm or "(unnamed)")
        for p in s.get("props") or []:
            add(f"section characteristic #{_bucket(nm + ':' + p, 50)}", f"{nm}:{p}")
    if sec.get("entry") is not None:
        add(f"entry-point section #{_bucket(sec['entry'], 10)}", sec["entry"] or "(none)")
    rich = raw.get("richheader") or []
    for i in range(0, len(rich) - 1, 2):
        add(f"tool #{_bucket(str(rich[i]), 32)}", f"comp.id {rich[i]}")
    return res


# --- classification (child process) -----------------------------------------------

def _classify(paths: list[str], mdir: str) -> list[dict[str, Any]]:
    import lightgbm as lgb
    import numpy as np

    from . import ember_features as ef

    thresholds = json.loads(THRESHOLDS_FILE.read_text()) if THRESHOLDS_FILE.is_file() else {}
    ex = ef.PEFeatureExtractor()
    names = feature_names(ex)
    boosters: dict[str, Any] = {}
    out = []
    for p in paths:
        rec: dict[str, Any] = {"path": p}
        try:
            path = Path(p)
            data = path.read_bytes()[:MAX_BYTES]
            ftype = file_type(data[:4096], path)
            if ftype is None:
                out.append({**rec, "status": "unsupported", "detail": "not a PE, PDF or ELF file"})
                continue
            model = ftype if (Path(mdir) / f"EMBER2024_{ftype}.model").is_file() else "all"
            mfile = Path(mdir) / f"EMBER2024_{model}.model"
            if not mfile.is_file():
                out.append({**rec, "status": "no_model", "file_type": ftype,
                            "detail": f"model EMBER2024_{ftype} (or _all) not provisioned in {mdir}"})
                continue
            b = boosters.get(model) or boosters.setdefault(model, lgb.Booster(model_file=str(mfile)))
            raw = ex.raw_features(data)
            vec = ex.process_raw_features(raw)
            nf = b.num_feature()
            if nf not in (ef.PE_DIM, ef.NON_PE_DIM) or nf > len(vec):
                out.append({**rec, "status": "error", "file_type": ftype, "model": model,
                            "detail": f"feature mismatch: model expects {nf}, extractor v{ef.FEATURE_VERSION} "
                                      f"gives {len(vec)}"})
                continue
            X = vec[:nf].reshape(1, -1)
            score = float(b.predict(X)[0])
            contrib = b.predict(X, pred_contrib=True)[0]           # nf values + bias
            th = (thresholds.get(model) or {}).get("threshold_fpr_0.01")
            blocks: dict[str, float] = {}
            for i in range(nf):
                blocks[names[i][0]] = blocks.get(names[i][0], 0.0) + float(contrib[i])
            hashed = _resolve_hashed(raw)
            order = np.argsort(-np.abs(contrib[:nf]))[:TOP_N]
            top = []
            for i in order:
                if contrib[i] == 0:
                    continue
                blk, nm = names[i]
                top.append({"block": blk, "feature": nm, "value": float(vec[i]),
                            "contribution": float(contrib[i]), "matches": hashed.get(nm, [])})
            out.append({**rec, "status": "ok", "file_type": ftype, "format": _FORMAT_LABEL.get(ftype, ftype),
                        "model": f"EMBER2024_{model}", "score": round(score, 6),
                        "threshold": th, "calibrated": th is not None,
                        "verdict": (None if th is None else ("above threshold" if score >= th else "below threshold")),
                        "metrics": {k: v for k, v in (thresholds.get(model) or {}).items()
                                    if k in ("tpr_at_fpr_0.01", "roc_auc", "challenge_pr_auc")},
                        "bias": float(contrib[-1]),
                        "blocks": dict(sorted(blocks.items(), key=lambda kv: -abs(kv[1]))),
                        "top_features": top, "feature_version": ef.FEATURE_VERSION})
        except Exception as exc:  # noqa: BLE001
            out.append({**rec, "status": "error", "detail": f"{type(exc).__name__}: {exc}"[:300]})
    return out


def classify(paths: list[Path], timeout: int | None = None) -> list[dict[str, Any]]:
    """Classify files in a child process. One record per path (same order)."""
    from ..config import tmo
    st = status()
    if not st["deps"]:
        return [{"path": str(p), "status": "not_installed",
                 "detail": "lightgbm / scikit-learn / signify not installed in the portable Python"} for p in paths]
    if not st["models"]:
        return [{"path": str(p), "status": "no_model",
                 "detail": f"EMBER2024 models not provisioned ({st['dir']}) — run install.py"} for p in paths]
    if not paths:
        return []
    try:
        r = subprocess.run([sys.executable, "-m", "docutracex.ml.ember_ml", str(models_dir()), *map(str, paths)],
                           capture_output=True, text=True, timeout=timeout or tmo(60 + 10 * len(paths)),
                           cwd=str(Path(__file__).resolve().parents[2]))
    except subprocess.TimeoutExpired:
        return [{"path": str(p), "status": "timeout", "detail": "classification timed out"} for p in paths]
    try:
        res = json.loads(r.stdout)
    except ValueError:
        err = (r.stderr or "").strip().splitlines()[-1:] or [f"exit {r.returncode}"]
        return [{"path": str(p), "status": "error", "detail": err[0][:300]} for p in paths]
    return res


if __name__ == "__main__":
    sys.stdout.write(json.dumps(_classify(sys.argv[2:], sys.argv[1]), default=float))
