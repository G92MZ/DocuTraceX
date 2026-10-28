"""Thresholds at 1% FPR (and 0.1%) per model from the per-type scores (CI helper)."""
import glob
import json

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

S = {f.split("scores_")[1][:-4]: dict(np.load(f)) for f in glob.glob("scores/**/scores_*.npz", recursive=True)}
res = {}


def metrics(y, s, yc, sc):
    out = {"n_test": int(len(y)), "roc_auc": float(roc_auc_score(y, s))}
    fpr, tpr, thr = roc_curve(y, s)
    for target in (0.01, 0.001):
        ok = np.where(fpr <= target)[0]
        i = ok[-1]
        out[f"threshold_fpr_{target}"] = float(thr[i])
        out[f"tpr_at_fpr_{target}"] = float(tpr[i])
    if len(sc):
        # challenge = malicious challenge files + benign test files (as in the paper)
        yb = np.concatenate([np.zeros(int((y == 0).sum())), np.ones(len(sc))])
        sb = np.concatenate([s[y == 0], sc])
        out["challenge_n"] = int(len(sc))
        out["challenge_pr_auc"] = float(average_precision_score(yb, sb))
        t = out["threshold_fpr_0.01"]
        out["challenge_detected_at_1pct_fpr"] = float((sc >= t).mean())
    return out


for t, d in S.items():                       # per-type model on its own type
    res[t] = metrics(d["y_test"], d[f"test_{t}"], d["y_chal"], d.get(f"chal_{t}", np.array([])))
for m, types in (("PE", ["Win32", "Win64", "Dot_Net"]), ("all", list(S))):
    have = [t for t in types if t in S and f"test_{m}" in S[t]]
    if have:
        y = np.concatenate([S[t]["y_test"] for t in have])
        s = np.concatenate([S[t][f"test_{m}"] for t in have])
        sc = np.concatenate([S[t][f"chal_{m}"] for t in have])
        res[m] = metrics(y, s, np.ones(len(sc)), sc)
        res[m]["types"] = have
json.dump(res, open("ember_models/thresholds.json", "w"), indent=2)
print(json.dumps(res, indent=2))
