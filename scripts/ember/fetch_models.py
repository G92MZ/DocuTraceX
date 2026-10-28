"""Download the EMBER2024 detection models and describe them (CI helper)."""
import hashlib
import json
import os
import shutil

import lightgbm as lgb
from huggingface_hub import hf_hub_download

REPO = "joyce8/EMBER2024-benchmark-models"
NAMES = ["Win32", "Win64", "Dot_Net", "PDF", "ELF", "APK", "PE", "all"]
out = "ember_models"
os.makedirs(out, exist_ok=True)
info = {}
for n in NAMES:
    fn = f"EMBER2024_{n}.model"
    p = hf_hub_download(repo_id=REPO, filename=fn)
    dst = os.path.join(out, fn)
    shutil.copyfile(p, dst)
    data = open(dst, "rb").read()
    b = lgb.Booster(model_file=dst)
    info[n] = {"file": fn, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
               "num_feature": b.num_feature(), "num_trees": b.num_trees(),
               "objective": (b.dump_model().get("objective") or ""),
               "feature_names_head": b.feature_name()[:5]}
    print(n, info[n])
json.dump(info, open(os.path.join(out, "models.json"), "w"), indent=2)
