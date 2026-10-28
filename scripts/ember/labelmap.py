"""Recover the index -> name mapping of the EMBER2024 family / tag models (CI helper).

The published models output class indices only; the map was built in a
non-deterministic order (multiprocessing imap_unordered) and never released.
With labelled EMBER2024 rows we match each output to the label it responds to:
tag models (one output per tag): AUC of each output against each tag, then a
1:1 assignment (Hungarian); family (multiclass): mean probability of each class
over the rows of each family, then a 1:1 assignment. Each mapping carries its
evidence (AUC / agreement, runner-up) so weak matches can be hidden."""
import glob
import json
import re
import sys

import lightgbm as lgb
import numpy as np
from huggingface_hub import hf_hub_download
from sklearn.metrics import roc_auc_score

IGNORE = {"", "win32", "win64", "elf", "linux", "pdf", "apk", "android"}
X = np.vstack([np.load(f) for f in sorted(glob.glob("samples/**/X_*.npy", recursive=True))])
L = sum([json.load(open(f)) for f in sorted(glob.glob("samples/**/L_*.json", recursive=True))], [])
print("rows", X.shape, len(L))
out = {}


def load(kind):
    import pickle
    p = hf_hub_download(repo_id="joyce8/EMBER2024-benchmark-models", filename=f"EMBER2024_{kind}.model")
    raw = open(p, "rb").read()
    print(kind, "size", len(raw), "head", repr(raw[:160]))
    boosters = []
    if raw[:1] == b"\x80":                       # a pickle (list of boosters / model strings)
        obj = pickle.loads(raw)
        items = obj if isinstance(obj, (list, tuple)) else [obj]
        for it in items:
            boosters.append(it if isinstance(it, lgb.Booster) else lgb.Booster(model_str=it))
    else:
        txt = raw.decode("utf-8", errors="replace")
        starts = [m.start() for m in re.finditer(r"(?m)^tree\n", txt)]
        print(kind, "'tree' headers:", len(starts), "num_class lines:", len(re.findall(r"(?m)^num_class=", txt)))
        if len(starts) <= 1:
            boosters = [lgb.Booster(model_str=txt)]
        else:
            starts.append(len(txt))
            boosters = [lgb.Booster(model_str=txt[a:b]) for a, b in zip(starts, starts[1:])]
    info = [{"num_class": b.num_model_per_iteration(), "num_trees": b.num_trees(), "num_feature": b.num_feature()}
            for b in boosters[:2]]
    print(kind, "boosters in file:", len(boosters), info)
    return boosters


def predict(boosters, Xs):
    cols = []
    for b in boosters:
        n = b.num_feature()
        pr = b.predict(Xs[:, :n] if n < Xs.shape[1] else Xs)
        cols.append(pr if pr.ndim == 2 else pr.reshape(-1, 1))
    return np.hstack(cols)


for kind in ("behavior", "packer", "exploit", "group", "file_property", "family"):
    try:
        boosters = load(kind)
    except Exception as exc:  # noqa: BLE001
        out[kind] = {"error": f"load: {exc}"}
        continue
    idx = [i for i, l in enumerate(L) if l.get(kind) or kind != "family"]
    names = sorted({x for i in idx for x in L[i][kind] if x not in IGNORE})
    Xs = X[idx]
    P = predict(boosters, Xs)
    K = P.shape[1]
    print(kind, "outputs", K, "candidate labels", len(names), "rows", len(idx))
    if kind != "family":
        Y = np.array([[1 if n in L[i][kind] else 0 for n in names] for i in idx], dtype=np.int8)
        keep = [j for j in range(len(names)) if 5 <= Y[:, j].sum() < len(idx)]
        names = [names[j] for j in keep]
        Y = Y[:, keep]
        S = np.zeros((K, len(names)))
        for k in range(K):
            for j in range(len(names)):
                S[k, j] = roc_auc_score(Y[:, j], P[:, k])
    else:
        fam = [L[i][kind][0] for i in idx]
        names = sorted({f for f in fam if f})
        pos = {n: [r for r, f in enumerate(fam) if f == n] for n in names}
        names = [n for n in names if len(pos[n]) >= 3]
        S = np.zeros((K, len(names)))
        top1 = P.argmax(1)
        for j, n in enumerate(names):
            S[:, j] = P[pos[n]].mean(0)
    m = {}
    if kind == "family":
        top1 = P.argmax(1)
        votes = {}                                 # output -> [(family, share of its rows, n)]
        for n in names:
            v = np.bincount(top1[pos[n]], minlength=K)
            k = int(v.argmax())
            votes.setdefault(k, []).append((n, float(v[k] / len(pos[n])), len(pos[n])))
        den = np.bincount(top1, minlength=K)
        for k, cands in votes.items():
            cands.sort(key=lambda x: (-x[1] * x[2], -x[1]))
            n, share, cnt = cands[0]
            m[k] = {"name": n, "agreement": round(share, 4), "n": cnt,
                    "purity": round(float(sum(1 for r in pos[n] if top1[r] == k) / max(den[k], 1)), 4),
                    "others": [c[0] for c in cands[1:4]]}
    else:
        for k in range(K):
            order = np.argsort(-S[k])
            j, j2 = int(order[0]), (int(order[1]) if len(order) > 1 else -1)
            mal = np.array([L[i].get("label") == 1 for i in idx])
            pred = P[:, k] >= 0.5
            tp = int((pred & mal & (Y[:, j] == 1)).sum())
            fp_mal = int((pred & mal & (Y[:, j] == 0)).sum())
            fp_ben = int((pred & ~mal).sum())
            m_extra = {"precision_mal": round(tp / max(tp + fp_mal, 1), 4),
                       "recall_mal": round(tp / max(int((mal & (Y[:, j] == 1)).sum()), 1), 4),
                       "fires_on_benign": round(fp_ben / max(int((~mal).sum()), 1), 4),
                       "trees": boosters[k].num_trees() if len(boosters) == K else None}
            # per-output threshold: the lowest score giving precision >= 0.8 among
            # malicious rows while firing on <= 0.2% of benign rows
            sc_m, y_m = P[mal, k], Y[mal, j]
            sc_b = P[~mal, k]
            best = None
            for t in np.unique(np.quantile(sc_m, np.linspace(0.5, 0.999, 120))):
                sel = sc_m >= t
                if sel.sum() < 3:
                    continue
                prec = float(y_m[sel].mean())
                fire = float((sc_b >= t).mean()) if len(sc_b) else 0.0
                if prec >= 0.8 and fire <= 0.002:
                    best = {"threshold": round(float(t), 6), "precision": round(prec, 4),
                            "recall": round(float(sel[y_m == 1].mean()) if y_m.sum() else 0.0, 4),
                            "benign_fire": round(fire, 5)}
                    break
            m_extra["calibrated"] = best
            m[k] = {**m_extra, "name": names[j], "auc": round(float(S[k, j]), 4),
                    "runner_up": names[j2] if j2 >= 0 else "",
                    "runner_up_auc": round(float(S[k, j2]), 4) if j2 >= 0 else None,
                    "mutual_best": int(np.argmax(S[:, j])) == k, "n": int(Y[:, j].sum())}
    out[kind] = {"outputs": K, "candidates": len(names), "map": {str(k): m[k] for k in sorted(m)}}
    good = sum(1 for v in m.values() if (v.get("agreement", 0) >= 0.5 if kind == "family" else (v["auc"] >= 0.9 and v["mutual_best"])))
    print(kind, "mapped", len(m), "of", K, "strong:", good)
json.dump(out, open("ember_models/label_maps.json", "w"), indent=1)
