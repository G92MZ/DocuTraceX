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
python run.py                 # every time: checks for updates, then starts the app
```

Every `python run.py` first **checks GitHub for a new version** and asks
`Update X.Y.Z -> A.B.C? [y/N]`. On `y` it updates, re-provisions the toolchain
(new tools get installed) and starts; on `N` (or with no Internet) it simply starts.
Then open `http://127.0.0.1:8000`.

??? tip "Other ways to run it"
    ```bash
    python run.py --port 8001       # next to another local app
    python run.py --host 127.0.0.1  # this computer only
    python run.py --no-update       # skip the update check (offline, scripts)
    ```
    By default it listens on every interface, so `http://<this machine's IP>:8000` works from
    another computer or a phone. `HOST` / `PORT` environment variables work too.

    Prefer pip? `pip install -r requirements.txt` installs the web service, and `python run.py`
    heals the portable toolchain on start. `install.py --force` reprovisions it.

## Updating

`python run.py` already offers each new version when it starts (see above). To update without
starting the app — your cases, rules, settings and tools are kept:

```bash
python update.py            # check and update (asks first)
python update.py --check    # only check
python update.py --yes      # update without asking
```

Cloned with git? `git pull` works too.

Once it runs, take five minutes for the [configuration](configuration.md): the proxy for network
checks, your own domains and brands, and, under **Detection rules**, your
[YARA rules](configuration.md#yara-rules) (folders on this machine or uploads, then **Recompile**)
and the folder of [Sigma registry rules](configuration.md#registry-sigma-rules) (a clone of SigmaHQ
and / or your own; optional).

## Your first case

1. **First start**: the app asks for the password of the **admin** user (see
   [Users, sign-in and audit](users.md)); then create accounts for your colleagues in **Users**.
2. Extract a sample from `samples/samples.zip` (password **`infected`**) — for example
   `email/sample.eml` — or run `python scripts/samplegen.py --extract`.
3. **New analysis** → drop the file. The original is copied, hashed and never modified; the
   analysis is queued and **Tasks** shows it step by step.
4. **Cases** → open it. **Components** has a tab per analysis: see the page for each
   [file type](file-types/email.md).

!!! note "The samples are inert"
    They tell one story — an invoice-fraud campaign against a supplier — with harmless indicators
    only: `*.example` domains, RFC 5737 IP addresses and stub binaries. The password keeps antivirus
    engines from flagging them.

## Where your data lives

| Folder | What |
|---|---|
| `cases/` | evidence, results, marks, task history, reports |
| `yara/` | the YARA rules you upload and the compiled set (folders you add are read in place) |
| `config/` | settings (proxy, AI endpoint, the Sigma rules folder's path) |
| `tools/` | the portable toolchain and reference data |

All of them are git-ignored and kept across updates. The Sigma rules stay in their own folder,
wherever you keep them (the app only reads them; update them with `git pull`). **Diagnostics** shows every dependency and
tool, with a **Retry** button to reinstall what is missing; see
[Tools and licences](TOOLS.md).
