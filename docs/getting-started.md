# Getting started

## Requirements

Python **3.10 or newer, 64-bit**, with `pip`, on Windows, Linux or macOS (x86-64 or ARM64), and
Internet access the first time.

Only a light web service is installed on your Python (`fastapi`, `uvicorn`, `jinja2`,
`python-multipart`). Every analysis library runs on a separate **portable Python** that the
installer downloads into `tools/`, so your environment is never touched and its version never
limits the analysis. No compiler, Build Tools or Java needed.

## Install and run

```bash
python install.py             # once: sets everything up
python run.py                 # then open http://127.0.0.1:8000
```

??? tip "Other ways to run it"
    ```bash
    python run.py --port 8001     # next to another local app
    ```
    `http://<this machine's IP>:8000` works from another computer or a phone; set
    `DOCUTRACEX_HOST=127.0.0.1` to keep it local.

    Prefer pip? `pip install -r requirements.txt` installs the web service, and `python run.py`
    heals the portable toolchain on start. `install.py --force` reprovisions it.

## Updating

`python run.py` checks for a new version on every start and asks before updating. On demand,
keeping your cases, rules, settings and tools:

```bash
python update.py            # check and update (asks first)
python update.py --check    # only check
```

## Your first case

1. Extract a sample from `samples/samples.zip` (password **`infected`**) — for example
   `email/sample.eml` — or run `python scripts/samplegen.py --extract`.
2. **New analysis** → drop the file. The original is copied, hashed and never modified; the
   analysis is queued and **Tasks** shows it step by step.
3. **Cases** → open it. **Components** has a tab per analysis: see the page for each
   [file type](file-types/email.md).

!!! note "The samples are inert"
    They tell one story — an invoice-fraud campaign against a supplier — with harmless indicators
    only: `*.example` domains, RFC 5737 IP addresses and stub binaries. The password keeps antivirus
    engines from flagging them.

## Where your data lives

| Folder | What |
|---|---|
| `cases/` | evidence, results, marks, task history, reports |
| `yara/` | your rules |
| `config/` | settings (proxy, AI endpoint) |
| `tools/` | the portable toolchain and reference data |

All of them are git-ignored and kept across updates. **Diagnostics** shows every dependency and
tool, with a **Retry** button to reinstall what is missing; see
[Tools and licences](TOOLS.md).
