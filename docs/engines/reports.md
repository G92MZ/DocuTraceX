# Reports, AI and MCP

## Report

One self-contained HTML report of what you **confirmed**: file hashes, the findings you marked
true positive with their evidence, the IOCs and C2 configurations you marked (or every IOC),
the nested tree and the Machine Learning results. Print it to PDF or attach it to a ticket.

![Report of sample.eml](../assets/shots/reports/report.webp){ .shot }

**Markdown (raw, for an LLM)** has one sub-tab per part of the analysis — summary, findings,
IOCs, stages, decrypted data, code, .NET, ML, C2, network checks, every module's raw JSON —
each with **Copy** and **Download**: paste it into any model or a ticket.

## AI and MCP

The **AI** tab answers questions about a case ("is this phishing? what would the macro do?")
with real data from it, through any **OpenAI-compatible endpoint** (your company's LiteLLM, a
provider), a **local model** (Ollama, LM Studio…), or an **MCP client** (Claude Desktop, Claude
Code) connected to `python -m docutracex.mcp_server`. The tab shows the exact configuration for
your installation.

### Connecting an MCP client

The **AI → MCP** tab shows every command below already filled in with your installation's paths
(the portable Python, the app folder and the cases folder), ready to copy.

=== "stdio (same machine)"

    The client starts the server itself. Claude Desktop: *Settings → Developer → Edit Config*
    and paste the `mcpServers` block from the tab. Claude Code:

    ```bash
    claude mcp add docutracex -e PYTHONPATH=<DocuTraceX> -e DOCUTRACEX_CASES_DIR=<DocuTraceX>/cases -- <python> -m docutracex.mcp_server
    ```

=== "HTTP (other machines, HTTP-only apps)"

    See [MCP over HTTP and its token](#mcp-over-http-and-its-token) below: start the server, then
    give the client the URL and the token.

### MCP over HTTP and its token

The server over HTTP answers at `http://<this machine>:8001/mcp` (MCP *streamable HTTP*) and
**every request needs a token** in the header `Authorization: Bearer <token>`; without it, or with an
old one, it answers **401**.

**1. Get the token.** It is created the first time it is needed and kept in `config/mcp_token.txt`
(git-ignored, kept across updates). Read it in **AI → MCP** (any signed-in user; **Copy token**), or
on the console of the machine:

```bash
python -m docutracex.users mcp-token
```

**2. Start the server** and leave it running (the **AI → MCP** tab has this command with your
paths filled in):

```powershell
# Windows (PowerShell), from any folder
$env:PYTHONPATH="<DocuTraceX>"; $env:DOCUTRACEX_CASES_DIR="<DocuTraceX>\cases"
& "<DocuTraceX>\tools\python\python.exe" -m docutracex.mcp_server --http --host 0.0.0.0 --port 8001
```

```bash
# Linux / macOS
PYTHONPATH=<DocuTraceX> DOCUTRACEX_CASES_DIR=<DocuTraceX>/cases \
  <DocuTraceX>/tools/python/bin/python3 -m docutracex.mcp_server --http --host 0.0.0.0 --port 8001
```

`--host 0.0.0.0` listens on every interface and accepts connections by IP or host name;
`--host 127.0.0.1` (the default) keeps it on this machine. On start it prints the URL and where to
find the token.

!!! warning "Use `--http`, not your own script"
    The token is checked by `python -m docutracex.mcp_server --http`. A hand-written script that
    starts the MCP server another way would serve it **without** the token: replace it with the
    command above.

**3. Configure the client** with the URL and the header — the **AI → MCP** tab shows these blocks
with your URL and token:

=== "OpenCode"

    In `opencode.json`:

    ```json
    {
      "mcp": {
        "docutracex": {
          "type": "remote",
          "url": "http://<this machine>:8001/mcp",
          "headers": { "Authorization": "Bearer <token>" },
          "enabled": true
        }
      }
    }
    ```

=== "Claude Code"

    ```bash
    claude mcp add --transport http docutracex http://<this machine>:8001/mcp --header "Authorization: Bearer <token>"
    ```

=== "Any other client"

    Add a *remote* / *HTTP* MCP server with the URL `http://<this machine>:8001/mcp` and the header
    `Authorization: Bearer <token>`.

**Regenerate the token** when it may have leaked or someone should lose access: **AI → MCP →
Regenerate** (admin), or `python -m docutracex.users mcp-token --regenerate`. The new token works at
once and the old one stops — no restart — so update every client with it.

!!! note "One token for the installation"
    Anyone with the token reads the cases (read-only), like any signed-in user. Give it only to
    people with an account, keep the port on a trusted network, and regenerate it when someone
    leaves.

All of them use the same **read-only** tools: case summary, findings with your marks, IOCs, any
analysis result, functions and their pseudocode, decrypted data, the nested tree, ML results and
network checks. None can modify a case or reach the network; the endpoint is only called when
you ask, and its key stays in your browser.
