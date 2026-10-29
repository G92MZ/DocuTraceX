"""Label map v4, step 1 (CI helper): per file type, stream labelled EMBER2024
rows (test, then train for families still short of rows), vectorise them with
the EMBER v3 extractor, run the family model and keep only AGGREGATES per
(family, output): sum of probabilities, top-1 counts and top-3 counts.
Usage: collect_family.py TYPE   (files chosen from ember_models/dataset_files.txt)"""
import json
import os
import re
import sys
import time
import zipfile

import lightgbm as lgb
import numpy as np
from huggingface_hub import hf_hub_download
from thrember.features import PEFeatureExtractor

ftype = sys.argv[1]
CAP = int(os.environ.get("CAP", "80"))            # rows per family
BUDGET = float(os.environ.get("BUDGET_MIN", "300")) * 60
BATCH = 2000
t0 = time.time()

listing = open("ember_models/dataset_files.txt").read().splitlines()
files = [ln.split()[1] for ln in listing if ln.startswith("joyce8/EMBER2024 ") and len(ln.split()) == 3]
mine = [f for f in files if re.search(rf"(^|[_/]){re.escape(ftype)}_(test|train)", f) and f.endswith(".zip")]
mine.sort(key=lambda f: (0 if "test" in f else 1, f))          # test first, then train
print(ftype, "files:", mine, flush=True)

model = lgb.Booster(model_file=hf_hub_download("joyce8/EMBER2024-benchmark-models", "EMBER2024_family.model"))
K = model.num_model_per_iteration()
NF = model.num_feature()
print("family model outputs", K, "features", NF, flush=True)

ex = PEFeatureExtractor()
names: dict[str, int] = {}
counts: list[int] = []
sums: list[np.ndarray] = []
top1: list[np.ndarray] = []
top3: list[np.ndarray] = []
total_sum = np.zeros(K)
total_rows = 0
seen = set()
batch_x, batch_f = [], []


def flush():
    global total_rows, total_sum
    if not batch_x:
        return
    X = np.vstack(batch_x).astype(np.float32)
    P = model.predict(X[:, :NF] if X.shape[1] > NF else X)
    order = np.argsort(-P, axis=1)[:, :3]
    for r, fam in enumerate(batch_f):
        j = names[fam]
        sums[j] += P[r]
        top1[j][order[r, 0]] += 1
        top3[j][order[r]] += 1
    total_sum += P.sum(0)
    total_rows += len(batch_f)
    batch_x.clear()
    batch_f.clear()


def done() -> bool:
    return time.time() - t0 > BUDGET


for fname in mine:
    if done():
        break
    short = {n: c for n, c in zip(names, counts) if c < CAP}
    if "train" in fname and names and not short:
        continue
    p = hf_hub_download(repo_id="joyce8/EMBER2024", filename=fname, repo_type="dataset")
    with zipfile.ZipFile(p) as z:
        for member in z.namelist():
            if not member.endswith(".jsonl") or done():
                continue
            with z.open(member) as fh:
                for line in fh:
                    r = json.loads(line)
                    fam = r.get("family")
                    fam = fam[0] if isinstance(fam, list) and fam else fam
                    if not fam or r.get("sha256") in seen:
                        continue
                    if fam in names and counts[names[fam]] >= CAP:
                        continue
                    seen.add(r.get("sha256"))
                    if fam not in names:
                        names[fam] = len(counts)
                        counts.append(0)
                        sums.append(np.zeros(K))
                        top1.append(np.zeros(K, dtype=np.int32))
                        top3.append(np.zeros(K, dtype=np.int32))
                    counts[names[fam]] += 1
                    batch_x.append(ex.process_raw_features(r))
                    batch_f.append(fam)
                    if len(batch_x) >= BATCH:
                        flush()
                        print(f"{fname}: families {len(names)} rows {total_rows} "
                              f"t={int(time.time() - t0)}s", flush=True)
    flush()
    os.remove(os.path.realpath(p))                       # keep the runner's disk free

order = sorted(names, key=names.get)
np.savez_compressed(f"agg_{ftype}.npz", sums=np.array(sums, dtype=np.float32), top1=np.array(top1),
                    top3=np.array(top3), counts=np.array(counts), total_sum=total_sum, total_rows=total_rows)
json.dump(order, open(f"agg_{ftype}.json", "w"))
print(ftype, "done: families", len(names), "rows", total_rows, "time", int(time.time() - t0), "s",
      "families with >=5 rows", sum(1 for c in counts if c >= 5), flush=True)
