"""SHA-256 of the tag/family models + tag pickles converted to plain LightGBM text (CI helper)."""
import hashlib
import json
import os
import pickle
import zipfile

from huggingface_hub import hf_hub_download

out = {}
os.makedirs("ember_models", exist_ok=True)
with zipfile.ZipFile("ember_models/tag_models_text.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for kind in ("behavior", "packer", "exploit", "group", "file_property", "family"):
        p = hf_hub_download(repo_id="joyce8/EMBER2024-benchmark-models", filename=f"EMBER2024_{kind}.model")
        raw = open(p, "rb").read()
        out[kind] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        if kind != "family":
            boosters = pickle.loads(raw)
            out[kind]["boosters"] = len(boosters)
            out[kind]["trees"] = [b.num_trees() for b in boosters]
            for i, b in enumerate(boosters):
                z.writestr(f"{kind}/{i:03d}.txt", b.model_to_string())
json.dump(out, open("ember_models/tag_models.json", "w"), indent=1)
print(json.dumps({k: {kk: vv for kk, vv in v.items() if kk != "trees"} for k, v in out.items()}, indent=1))
