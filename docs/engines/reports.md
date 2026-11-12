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

All of them use the same **read-only** tools: case summary, findings with your marks, IOCs, any
analysis result, functions and their pseudocode, decrypted data, the nested tree, ML results and
network checks. None can modify a case or reach the network; the endpoint is only called when
you ask, and its key stays in your browser.
