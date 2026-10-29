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

## Family / tag label maps (`ember_labels.json`)

The EMBER2024 family, behaviour, packer, exploit, group and file-property models
output class indices only; the authors never published the index → name maps
(and their own code builds them in a non-deterministic order). DocuTraceX
reconstructed them:

4. `tagmodels.py` — SHA-256 of the tag/family models; the tag models (pickled
   lists of LightGBM Boosters) re-saved as plain text boosters.
5. `collect.py TYPE` — a labelled sample of each type's test set (up to 25
   files per family, 400 per tag, plus random files): 67,806 files.
6. `labelmap.py` — tag outputs matched to the tag they rank best (ROC AUC,
   mutual best), with precision / recall / benign firing rate and a per-output
   threshold (precision ≥ 0.8 on malicious files, ≤ 0.2% benign firing); family
   outputs matched by majority vote of each family's files (agreement, purity).

The sample over-represents rare tags/families, so real-world precision of rare
labels is lower than measured.

### Family label map v4

v3 named only 987 of the family model's 2,538 outputs: it voted with each
family's top-1 output, and a few popular outputs (generic names such as
*wacatac*) win top-1 for files of hundreds of families. v4 (CI run on a
temporary branch, ~25 min):

7. `collect_family.py TYPE` — streams the labelled EMBER2024 test **and train**
   sets (up to 80 files per family; 175,059 files, 6,776 families in all),
   runs the family model and keeps only aggregates per (family, output): sum
   of probabilities, top-1 and top-3 counts.
8. `labelmap_family_v4.py` — names an output after the family whose files
   raise it most *specifically* (mean probability ÷ mean over all files) when
   family and output are each other's best match; confidence from top-3
   purity (high ≥ 0.6 with ≥ 5 files, medium ≥ 0.35).

Merged into `ember_labels.json`: v4 names (high / medium), v3 names where v4
named nothing, v4 winning conflicts when its confidence is high; an output
whose name another output already carries (with stronger evidence) is left
unnamed. Result: **2,462 of 2,538 outputs named** (2,208 high, 254 medium);
v4 reproduced 827 of the 849 v3 names it could compare (97%).
`docutracex/ml/family_info.json` describes what each named family is.
