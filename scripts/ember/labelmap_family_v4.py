"""Label map v4, step 2 (CI helper): name the family model's outputs from the
per-type aggregates of collect_family.py.

v3 named an output only when a family's files mostly had it as their TOP-1
output; popular outputs (generic names such as 'wacatac') win top-1 for many
families, so 1,551 of 2,538 outputs stayed unnamed. v4 looks at what is
SPECIFIC to each family:

  mean[f, k]  = mean probability of output k over family f's files
  lift[f, k]  = mean[f, k] / mean probability of k over all files
  an output k is named f when f is k's best family by lift AND k is f's best
  output by lift (mutual best), with enough evidence.

Confidence (per output, with the evidence kept):
  purity3 = share of all files having k in their top-3 that are family f
  high    mutual best, n >= 5, purity3 >= 0.6, mean >= 0.05
  medium  mutual best, n >= 3, purity3 >= 0.35
The v3 names are kept for comparison (how many v3 high names v4 reproduces).
"""
import glob
import json

import numpy as np

per = []
for f in sorted(glob.glob("aggs/**/agg_*.npz", recursive=True)):
    d = np.load(f)
    names = json.load(open(f[:-4] + ".json"))
    per.append((names, d))
    print(f, "families", len(names), "rows", int(d["total_rows"]))

allnames = sorted({n for names, _ in per for n in names})
idx = {n: i for i, n in enumerate(allnames)}
K = per[0][1]["sums"].shape[1]
F = len(allnames)
sums = np.zeros((F, K))
top1 = np.zeros((F, K), dtype=np.int64)
top3 = np.zeros((F, K), dtype=np.int64)
counts = np.zeros(F, dtype=np.int64)
total_sum = np.zeros(K)
total_rows = 0
for names, d in per:
    rows = [idx[n] for n in names]
    sums[rows] += d["sums"]
    top1[rows] += d["top1"]
    top3[rows] += d["top3"]
    counts[rows] += d["counts"]
    total_sum += d["total_sum"]
    total_rows += int(d["total_rows"])
print("families", F, "outputs", K, "rows", total_rows)

ok = counts >= 3
mean = np.divide(sums, counts[:, None], out=np.zeros_like(sums), where=counts[:, None] > 0)
base = total_sum / max(total_rows, 1)
lift = mean / (base[None, :] + 1e-9)
lift[~ok] = 0
best_out = lift.argmax(1)                     # family -> output
best_fam = lift.argmax(0)                     # output -> family
col3 = top3.sum(0)
col1 = top1.sum(0)

m = {}
for k in range(K):
    f = int(best_fam[k])
    if not ok[f] or best_out[f] != k or lift[f, k] <= 1:
        continue
    n = int(counts[f])
    p3 = float(top3[f, k] / col3[k]) if col3[k] else 0.0
    rec = {"name": allnames[f], "n": n, "lift": round(float(lift[f, k]), 2), "mean": round(float(mean[f, k]), 4),
           "purity3": round(p3, 4), "agreement": round(float(top1[f, k] / n), 4),
           "purity": round(float(top1[f, k] / col1[k]), 4) if col1[k] else 0.0}
    if n >= 5 and p3 >= 0.6 and rec["mean"] >= 0.05:
        rec["confidence"] = "high"
    elif p3 >= 0.35:
        rec["confidence"] = "medium"
    else:
        rec["confidence"] = "low"
    m[str(k)] = rec

named = {k: v for k, v in m.items() if v["confidence"] in ("high", "medium")}
print("v4 mutual-best outputs", len(m), "named (high+medium)", len(named),
      "high", sum(1 for v in named.values() if v["confidence"] == "high"))

# compare with v3 (the map shipped today)
try:
    v3 = json.load(open("docutracex/ml/ember_labels.json"))["models"]["family"]["labels"]
    same = sum(1 for k, v in v3.items() if named.get(k, {}).get("name") == v["name"])
    diff = [(k, v["name"], named[k]["name"]) for k, v in v3.items() if k in named and named[k]["name"] != v["name"]]
    lost = [k for k in v3 if k not in named]
    print("v3 names", len(v3), "same in v4", same, "different", len(diff), "not named in v4", len(lost))
    print("examples of differences", diff[:25])
except Exception as exc:  # noqa: BLE001
    print("v3 compare failed", exc)

json.dump({"outputs": K, "families_seen": F, "rows": total_rows, "map": m}, open("ember_models/family_map_v4.json", "w"),
          indent=1)
