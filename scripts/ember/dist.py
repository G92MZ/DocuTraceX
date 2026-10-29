"""EMBER2024 reference distributions for one file type (CI helper).

Streams the labelled TYPE_test set, keeps up to N malicious + N benign files
(spread over the whole set), vectorises them with the EMBER v3 extractor and,
with the TYPE detection model, records:
  score   quantiles of the model score (0..100%) for malicious and benign files
  feat    per feature (the model's input columns): share of files where it is
          non-zero, and quantiles of |value| (p1 p5 p10 p25 p50 p75 p90 p95 p99),
          for malicious and benign files
Usage: dist.py TYPE  ->  dist_TYPE.json"""
import json
import os
import random
import sys
import time
import zipfile

import lightgbm as lgb
import numpy as np
from huggingface_hub import hf_hub_download
from thrember.features import PEFeatureExtractor

ftype = sys.argv[1]
N = int(os.environ.get("PER_CLASS", "20000"))
Q = [1, 5, 10, 25, 50, 75, 90, 95, 99]
random.seed(1)
t0 = time.time()
model = lgb.Booster(model_file=hf_hub_download("joyce8/EMBER2024-benchmark-models", f"EMBER2024_{ftype}.model"))
nf = model.num_feature()
p = hf_hub_download(repo_id="joyce8/EMBER2024", filename=f"{ftype}_test.zip", repo_type="dataset")
ex = PEFeatureExtractor()
rows = {0: [], 1: []}
seen = 0
with zipfile.ZipFile(p) as z:
    names = [m for m in z.namelist() if m.endswith(".jsonl")]
    total = 0
    for m in names:                       # first pass: count, to sample evenly
        with z.open(m) as fh:
            total += sum(1 for _ in fh)
    keep = min(1.0, 2.6 * N / max(total, 1))
    print(ftype, "rows in test set", total, "keep prob", round(keep, 3), flush=True)
    for m in names:
        with z.open(m) as fh:
            for line in fh:
                if random.random() > keep:
                    continue
                r = json.loads(line)
                lab = r.get("label")
                if lab not in (0, 1) or len(rows[lab]) >= N:
                    continue
                rows[lab].append(ex.process_raw_features(r)[:nf])
                seen += 1
                if seen % 5000 == 0:
                    print(ftype, "kept", len(rows[0]), len(rows[1]), int(time.time() - t0), "s", flush=True)
out = {"model": f"EMBER2024_{ftype}", "n": {"malicious": len(rows[1]), "benign": len(rows[0])},
       "quantiles": Q, "score": {}, "feat": {}}
for lab, key in ((1, "malicious"), (0, "benign")):
    X = np.vstack(rows[lab]).astype(np.float32)
    s = model.predict(X)
    out["score"][key] = [round(float(v), 6) for v in np.quantile(s, np.linspace(0, 1, 101))]
    A = np.abs(X)
    nz = (A > 0).mean(0)
    qs = np.quantile(A, [q / 100 for q in Q], axis=0)          # (len(Q), nf)
    out["feat"][key] = {"nz": [round(float(v), 4) for v in nz],
                        "q": [[float(f"{v:.4g}") for v in qs[:, i]] for i in range(nf)]}
json.dump(out, open(f"dist_{ftype}.json", "w"), separators=(",", ":"))
print(ftype, "done", out["n"], int(time.time() - t0), "s", "size", os.path.getsize(f"dist_{ftype}.json"), flush=True)
