"""Collect a labelled sample of ONE file type of the EMBER2024 test set (CI helper).

Keeps, per label value, up to CAP rows (family / behavior / packer / exploit /
group / file_property) plus some unlabelled rows, vectorised with the EMBER v3
extractor. Usage: collect.py TYPE"""
import json
import os
import random
import sys
import zipfile

import numpy as np
from huggingface_hub import hf_hub_download
from thrember.features import PEFeatureExtractor

ftype = sys.argv[1]
KINDS = ("family", "behavior", "packer", "exploit", "group", "file_property")
CAP = {"family": 25, "behavior": 400, "packer": 400, "exploit": 400, "group": 200, "file_property": 400}
random.seed(0)
work = f"data_{ftype}"
os.makedirs(work, exist_ok=True)
p = hf_hub_download(repo_id="joyce8/EMBER2024", filename=f"{ftype}_test.zip", repo_type="dataset")
with zipfile.ZipFile(p) as z:
    z.extractall(work)
os.remove(os.path.realpath(p))
files = sorted({os.path.join(dp, f) for dp, _, fs in os.walk(work) for f in fs if f.endswith(".jsonl")})
seen_sha = set()
counts = {k: {} for k in KINDS}
ex = PEFeatureExtractor()
X, L = [], []
first = True
for f in files:
    with open(f) as fh:
        for line in fh:
            r = json.loads(line)
            if first:
                print("keys:", {k: (type(r.get(k)).__name__, r.get(k)) for k in ("label",) + KINDS})
                first = False
            sha = r.get("sha256")
            if sha in seen_sha:
                continue
            seen_sha.add(sha)
            labs = {}
            take = False
            for k in KINDS:
                v = r.get(k)
                vals = [v] if isinstance(v, str) else (v or [])
                vals = [x for x in vals if x]
                labs[k] = vals
                for x in vals:
                    c = counts[k].get(x, 0)
                    if c < CAP[k]:
                        take = True
            if not take and random.random() < 0.01:
                take = True
            if not take:
                continue
            for k, vals in labs.items():
                for x in vals:
                    counts[k][x] = counts[k].get(x, 0) + 1
            X.append(ex.process_raw_features(r))
            L.append({"label": r.get("label"), **labs})
np.save(f"X_{ftype}.npy", np.vstack(X).astype(np.float32))
json.dump(L, open(f"L_{ftype}.json", "w"))
print(ftype, "rows", len(L), {k: len(v) for k, v in counts.items()})
