"""Score the EMBER2024 test (and challenge) set of ONE file type with the
detection models and save scores + labels (CI helper). Usage: calibrate.py TYPE"""
import json
import os
import sys
import zipfile

import lightgbm as lgb
import numpy as np
from huggingface_hub import hf_hub_download
from thrember.features import PEFeatureExtractor

ftype = sys.argv[1]
work = f"data_{ftype}"
os.makedirs(work, exist_ok=True)
for fn in (f"{ftype}_test.zip", "challenge.zip"):
    p = hf_hub_download(repo_id="joyce8/EMBER2024", filename=fn, repo_type="dataset")
    with zipfile.ZipFile(p) as z:
        z.extractall(work)
    os.remove(os.path.realpath(p))
files = sorted(os.path.join(dp, f) for dp, _, fs in os.walk(work) for f in fs if f.endswith(".jsonl"))
print("files", files[:5], len(files))

models = {m: lgb.Booster(model_file=f"ember_models/EMBER2024_{m}.model")
          for m in {ftype, "all", *(["PE"] if ftype in ("Win32", "Win64", "Dot_Net") else [])}}
ex = PEFeatureExtractor()
TYPE_KEYS = ("file_type", "filetype", "type")
first_keys = None


def rows(subset):
    global first_keys
    for f in files:
        if subset not in os.path.basename(f):
            continue
        with open(f) as fh:
            for line in fh:
                r = json.loads(line)
                if first_keys is None:
                    first_keys = sorted(k for k in r if not isinstance(r[k], (dict, list)))
                if subset == "challenge":
                    t = next((r[k] for k in TYPE_KEYS if k in r), None)
                    if t is not None and str(t).lower().replace(".", "").replace("_", "") != ftype.lower().replace("_", ""):
                        continue
                lab = r.get("label")
                if lab not in (0, 1):
                    continue
                yield r, lab


def score(subset):
    out = {m: [] for m in models}
    ys, batch = [], []
    def flush():
        if not batch:
            return
        X = np.vstack(batch)
        for m, b in models.items():
            n = b.num_feature()
            out[m].append(b.predict(X[:, :n] if n < X.shape[1] else X))
        batch.clear()
    for r, lab in rows(subset):
        batch.append(ex.process_raw_features(r))
        ys.append(lab)
        if len(batch) >= 5000:
            flush()
    flush()
    return {m: (np.concatenate(v) if v else np.array([])) for m, v in out.items()}, np.array(ys)


te, yte = score("test")
ch, ych = score("challenge")
np.savez_compressed(f"scores_{ftype}.npz", y_test=yte, y_chal=ych,
                    **{f"test_{m}": v for m, v in te.items()}, **{f"chal_{m}": v for m, v in ch.items()})
print("first row scalar keys:", first_keys)
print(ftype, "test", len(yte), "malicious", int(yte.sum()), "challenge", len(ych))
