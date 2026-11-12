"""Families covered in depth by the C2 tab: what each one is and what the app
reads from it. Shown in the C2 tab (*Families*) and at the top of the C2
section of the Markdown export (only the families present in the case).

Only families whose extractor is complete get a card; the others stay in the
extractor table until they are worked on.
"""

from __future__ import annotations

from typing import Any

FAMILIES: list[dict[str, Any]] = [
    {
        "id": "cobalt",
        "name": "Cobalt Strike",
        "match": ("Cobalt Strike",),
        "what": "Commercial adversary-simulation framework. Its implant, the *beacon*, is used by red teams and, "
                "from leaked and cracked builds, by ransomware affiliates and many intrusion sets.",
        "arrives": "As a stager (PowerShell / HTA / VBA / shellcode that downloads the beacon), a loader that "
                   "decrypts it in memory, an artifact-kit EXE / DLL, or a full beacon in a dropper or a memory dump.",
        "reads": ["configuration read by two parsers and compared (1768.py and dissect.cobaltstrike)",
                  "C2 hosts and URIs, user agent, sleep / jitter, named pipe, spawn-to, kill date",
                  "DNS channel, peer-to-peer (SMB / TCP), process injection and evasion (sleep mask, syscalls)",
                  "guardrails (who the beacon is keyed to), the team server's RSA key, rebuilt malleable profile",
                  "watermark with its meaning (trial, known leaked / cracked); stagers by the request they make"],
        "next": "Hunt the C2 hosts, URIs, user agent and pipe names; the RSA key and a non-shared watermark link "
                "samples of the same team server.",
        "limits": "A beacon only decrypted in memory by a custom loader needs that layer decoded first; "
                  "a watermark identifies a licence, never an actor.",
    },
    {
        "id": "asyncrat",
        "name": "AsyncRAT / DcRAT",
        "match": ("AsyncRAT", "DcRAT", "QuasarRAT", "AsyncRAT / Quasar family", "VenomRAT"),
        "what": "Open-source .NET remote-access trojans (AsyncRAT and its forks DcRAT and VenomRAT, from the "
                "Quasar lineage): remote control, keylogging, file transfer and plugins; common in commodity "
                "phishing campaigns.",
        "arrives": "Usually the last stage of a loader chain: a script, an ISO / ZIP or an Office document drops a "
                   ".NET loader that decrypts the client from a resource, a bitmap or a download.",
        "reads": ["settings decrypted statically (AES-256 + HMAC with the PBKDF2 key, or Quasar 1.3's AES-128) and "
                  "named by their field in the settings class (Hosts, Ports, MTX, Pastebin…)",
                  "second engine: rat-king-parser, compared with the own decoder",
                  "C2 hosts and ports, or the Pastebin dead drop the C2 is fetched from",
                  "install path and persistence (scheduled task or Run key), anti-analysis, BSOD-on-kill, delay",
                  "the server certificate the client pins (CN, validity, SHA-1) — links samples of the same server",
                  "builder defaults flagged as such; traces only when the settings do not decrypt"],
        "next": "Hunt the hosts / ports and the paste; the certificate SHA-1 links clients of one server; look for "
                "the mutex, the install path and the task / Run key on the endpoints.",
        "limits": "A loader that is not unpacked hides the client (analyse the whole file, or tick *also its "
                  "contents*); forks with another salt only give traces.",
    },
    {
        "id": "rmm",
        "name": "RMM / remote-access tools",
        "match": ("RMM: ",),
        "what": "Legitimate remote monitoring and management or remote-support software (ScreenConnect, AnyDesk, "
                "Atera, NetSupport, TeamViewer… ~360 from the LOLRMM catalogue). Abused for persistent access "
                "because it is signed and allowed.",
        "arrives": "Fake invoices, support scams and fake updates that make the victim install the client — often a "
                   "trojanised installer bound to the attacker's own instance.",
        "reads": ["the product, from file names, PE metadata, code-signing signers and domains (LOLRMM, weekly)",
                  "the instance it is bound to: ScreenConnect relay and session type, Atera account, NetSupport "
                  "gateway, MeshCentral server, Tactical RMM API…",
                  "in every analysis, without running C2; product names in emails and documents "
                  "(rmm:mention) and IOCs tagged with the product"],
        "next": "Ask whether the organisation uses that product and owns that instance; if not, hunt the relay / "
                "account and report the instance to the vendor.",
        "limits": "The product alone is no proof of an intrusion; an instance typed by the victim or downloaded "
                  "later is not in the file.",
    },
]


def for_family(family: str) -> dict[str, Any] | None:
    f = str(family or "")
    for fam in FAMILIES:
        if any(f == m or (m.endswith(" ") and f.startswith(m)) for m in fam["match"]):
            return fam
    return None


def markdown(families: list[str]) -> str:
    """The cards of the families present, as Markdown (empty when none has one)."""
    seen: list[dict[str, Any]] = []
    for f in families:
        fam = for_family(f)
        if fam and fam not in seen:
            seen.append(fam)
    out = []
    for fam in seen:
        out += [f"### About {fam['name']}", "", fam["what"], "", f"- **How it arrives:** {fam['arrives']}",
                "- **What DocuTraceX reads:**"] + [f"  - {r}" for r in fam["reads"]] + [
                f"- **Next:** {fam['next']}", f"- **Limits:** {fam['limits']}", ""]
    return "\n".join(out)
