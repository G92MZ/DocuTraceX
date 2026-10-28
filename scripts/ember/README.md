# EMBER2024 model calibration (Machine Learning tab)

`docutracex/ml/ember_thresholds.json` pins the EMBER2024 detection models
(SHA-256, feature count) and the **score threshold at a 1% false-positive rate**
per model, computed on the EMBER2024 test set of each file type, plus the share
of the challenge set (evasive malware) caught at that threshold.

It was produced with these scripts on a GitHub Actions runner (the models and
the dataset live on Hugging Face, ~10 GB of test features):

1. `fetch_models.py` — downloads the detection models, records size/sha256/num_feature.
2. `calibrate.py TYPE` — for `PDF`, `ELF`, `Dot_Net`, `Win64`, `Win32`: downloads
   `TYPE_test.zip` + `challenge.zip` from `joyce8/EMBER2024`, vectorises the raw
   features (thrember, `signify==0.7.1`, patched oscrypto) and scores them with
   the per-type, `PE` and `all` models.
3. `summarize.py` — thresholds at 1% / 0.1% FPR, TPR, ROC AUC and challenge
   detection per model → `thresholds.json`.

Note: the test jsonl files were read twice (duplicate rows), which does not
change ROC AUC, thresholds or TPR, but biases a challenge PR AUC — that metric
is therefore not kept; the challenge **detection rate** at the threshold is.
