"""The families of the C2 tab: what each one is and what the app
reads from it. Shown in the C2 tab (*Families*) and at the top of the C2
section of the Markdown export (only the families present in the case).

Every family an extractor knows has a card; its *Limits* say what is not read yet.
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
        "name": "AsyncRAT / DcRAT / QuasarRAT",
        "match": ("AsyncRAT", "DcRAT", "QuasarRAT", "AsyncRAT / Quasar family", "VenomRAT"),
        "what": "Open-source .NET remote-access trojans (AsyncRAT and its forks DcRAT and VenomRAT, from the "
                "Quasar lineage): remote control, keylogging, file transfer and plugins; common in commodity "
                "phishing campaigns.",
        "arrives": "Usually the last stage of a loader chain: a script, an ISO / ZIP or an Office document drops a "
                   ".NET loader that decrypts the client from a resource, a bitmap or a download.",
        "reads": ["settings decrypted statically (AES-256 + HMAC with the PBKDF2 key, or Quasar 1.3's AES-128) and "
                  "named by their field in the settings class (AsyncRAT / DcRAT: Hosts, Ports, MTX, Pastebin…; Quasar: HOSTS, MUTEX, TAG, STARTUPKEY…)",
                  "second engine: rat-king-parser, compared with the own decoder",
                  "C2 hosts and ports, or the Pastebin dead drop the C2 is fetched from",
                  "install path and persistence (scheduled task or Run key), anti-analysis, BSOD-on-kill, delay, keylogger",
                  "the server certificate the client pins (CN, validity, SHA-1) — links samples of the same server",
                  "builder defaults flagged as such; traces only when the settings do not decrypt"],
        "next": "Hunt the hosts / ports and the paste; the certificate SHA-1 links clients of one server; look for "
                "the mutex, the install path and the task / Run key on the endpoints.",
        "limits": "A loader that is not unpacked hides the client (analyse the whole file, or tick *also its "
                  "contents*); forks with another salt only give traces.",
    },
    {
        "id": "remcos",
        "name": "Remcos",
        "match": ("Remcos",),
        "what": "Commercial remote-administration tool sold by Breaking-Security, widely used by criminals as a "
                "RAT: remote control, keylogging, screenshots, audio and webcam capture, file and process management.",
        "arrives": "Phishing attachments (invoices, shipping notices) that run a script, an Office document or an "
                   "ISO / ZIP; often unpacked in memory by a loader (GuLoader and the like) before it runs.",
        "reads": ["the RC4-encrypted SETTINGS resource (the key travels in the resource itself)",
                  "C2 host:port entries with their TLS flag, botnet (campaign) name, reconnect interval, version",
                  "Remcos 3.x / 4.x by field position: install folder and name (hidden), persistence (Run keys, "
                  "Winlogon), process injection, mutex",
                  "keylogger (mode, log file, encrypted / hidden) and screenshots (folder, interval)",
                  "builder defaults flagged; older layouts read generically; traces only when there is no resource"],
        "next": "Hunt the C2 hosts and ports and the mutex; look for the install path, the Run value and the "
                "keylog / screenshot folders on the endpoints.",
        "limits": "A loader that is not unpacked hides the payload; the install folder can be a builder code "
                  "(shown as such); later positions (audio, anti-analysis, licence) are left as numbered fields.",
    },
    {
        "id": "xworm",
        "name": "XWorm",
        "match": ("XWorm", "XWorm-like RAT"),
        "what": "Commodity .NET RAT sold as a builder (and leaked / cracked): remote control, keylogging, USB "
                "spreading, plugins, DDoS and ransomware modules; often announces new victims over Telegram.",
        "arrives": "Script or shortcut chains (VBS / JS / PowerShell / LNK) and loaders that decrypt the client "
                   "in memory, from phishing attachments and fake downloads.",
        "reads": ["the settings decrypted statically (AES-256-ECB, key from MD5 of the mutex) and named by their "
                  "field in the settings class (Hosts, Port, Groub, USBNM, InstallDir / InstallStr, Sleep, "
                  "LoggerPath, ChatID / Token…)",
                  "C2 hosts and ports, group, mutex, version, splitter",
                  "install path and persistence (scheduled task, Run key, Startup shortcut), USB spreading name, "
                  "keylogger log, start delay",
                  "Telegram bot token / chat ID marked sensitive; without the names the values are read by what "
                  "they look like, and traces only when nothing decrypts"],
        "next": "Hunt the hosts / ports; look for the mutex, the install path, the task / Run value / Startup "
                "shortcut and the USB copy on endpoints; the bot token is the operator's — evidence, not a login.",
        "limits": "A loader that is not unpacked hides the client; builds that change the key derivation only "
                  "give traces.",
    },
    {
        "id": "snake",
        "name": "Snake Keylogger",
        "match": ("Snake Keylogger", "Snake-like keylogger"),
        "what": "Commodity .NET keylogger and credential stealer (also sold as 404 Keylogger): keystrokes, "
                "clipboard, screenshots and saved browser / mail / FTP credentials, sent out by mail, FTP or Telegram.",
        "arrives": "Invoice and purchase-order phishing: an archive or Office document that drops a loader, which "
                   "decrypts the keylogger in memory.",
        "reads": ["the strings decrypted statically (DES-ECB, key from MD5 of a string of the binary)",
                  "the exfiltration channel: SMTP server, port, sender and receiver, the password by its position "
                  "after the sender; FTP URL, user and password; Telegram bot token and chat ID",
                  "credentials marked sensitive; the banner; traces only when nothing decrypts"],
        "next": "Hunt the mail / FTP server and the accounts; report the mailbox or the bot to its provider; "
                "the credentials are the operator's — evidence, not a login.",
        "limits": "A loader that is not unpacked hides the keylogger; the order of the settings decides the "
                  "password, so it is shown as taken by position; option flags (screenshots, clipboard…) are not read.",
    },
    {
        "id": "redline",
        "name": "RedLine / META Stealer",
        "match": ("RedLine Stealer", "META Stealer"),
        "what": "Commodity .NET infostealers sold as malware-as-a-service (META is a RedLine clone): saved "
                "browser passwords, cookies and cards, crypto wallets, VPN / FTP / messenger credentials, system "
                "profile.",
        "arrives": "Fake software downloads and cracks, malvertising, and phishing attachments that drop a loader.",
        "reads": ["IP (the panel, host:port, several joined by |) and ID (the build tag) decrypted statically "
                  "(base64 + XOR with a key string + base64)",
                  "with dnfile + dncil the settings class names them (IP, ID, Message, Key): the fake error "
                  "message shown to the victim too",
                  "RedLine or META by its strings; traces only when nothing decrypts"],
        "next": "Hunt the panel host:port; the build ID groups samples of the same customer build.",
        "limits": "What it steals is asked from the panel (WCF net.tcp) at run time, so it is not in the file; "
                  "builds with another string encryption only give traces.",
    },
    {
        "id": "warzone",
        "name": "Warzone / AveMaria",
        "match": ("Warzone / AveMaria",),
        "what": "Native C++ RAT sold as a service: remote desktop and hidden RDP, UAC bypass, keylogger "
                "(online and offline), credential theft from browsers and mail clients, reverse proxy.",
        "arrives": "Phishing attachments (Office documents with exploits or macros, archives) that drop or "
                   "inject it, often through a loader.",
        "reads": ["the .bss configuration decrypted statically (RC4 with the key stored next to it)",
                  "C2 host:port, the RC4 key and the version (warzoneNNN)",
                  "the builder options after the port, shown raw (their layout changes between versions)",
                  "traces (Ave_Maria, UAC bypass moniker, _rptls key, rdpwrap) — alone when nothing decrypts"],
        "next": "Hunt the C2 host:port; look for the HKCU\\Software\\_rptls key, added RDP users and "
                "rdpwrap on endpoints.",
        "limits": "Install / startup / keylogger options are not named until real samples confirm the layout; "
                  "a packed or injected payload has to be unpacked first.",
    },
    {
        "id": "raccoon",
        "name": "Raccoon Stealer v2",
        "match": ("Raccoon Stealer v2", "RC4-encrypted C2 (Raccoon-like)"),
        "what": "Native infostealer sold as malware-as-a-service (v2, \"RecordBreaker\"): browser passwords, "
                "cookies and cards, crypto wallets, files, screenshots; can download and run more malware.",
        "arrives": "Cracked-software and fake-download sites, malvertising and loader chains.",
        "reads": ["its strings decrypted statically (base64 + RC4 with a key string of the binary)",
                  "every C2 URL, the request fields (machineId / configId), the user agent and a 32-hex config ID "
                  "when present (marked as probable)",
                  "traces (browser DLLs, wallet files) — and, alone, only together with its own request fields"],
        "next": "Hunt the C2 URLs and the user agent; the config ID links samples of the same customer build.",
        "limits": "What it steals, the DLLs it downloads and its file grabbers come from the C2 at check-in, "
                  "so they are not in the file.",
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
    {
        "id": "njrat",
        "name": "njRAT",
        "match": ("njRAT",),
        "what": "Old, free .NET RAT (also Bladabindi) still everywhere in commodity campaigns: remote control, "
                "keylogging, webcam, USB spreading, plugins.",
        "arrives": "Script and archive chains, cracked software, USB drives; often packed or crypted.",
        "reads": ["the settings from the .NET strings: C2 host and port (or the separator-split list), campaign, "
                  "version, install folder and name, the registry key it keeps its data in",
                  "the field separator, including builders that change it"],
        "next": "Hunt the host:port and the install name; look for the Run value and the firewall exception it adds.",
        "limits": "A crypter (TilesToPicture, KoiVM…) has to be unpacked first — or read a memory dump.",
    },
    {
        "id": "nanocore",
        "name": "NanoCore",
        "match": ("NanoCore",),
        "what": "Commercial .NET RAT (leaked / cracked): remote control, keylogging, plugins; still sold in "
                "crypted form.",
        "arrives": "Phishing attachments that run a multi-layer .NET crypter before the client.",
        "reads": ["identification of the client and of the crypter layers it sits under (RC4 stage 2, Tyrone DLL)",
                  "the decrypted later stages as children, so their own strings and IOCs are read"],
        "next": "Use a memory dump of the running client to get its settings; hunt what the crypter stages reveal.",
        "limits": "The settings resource (DES / Rijndael with the GUID) is not decrypted yet: identification only.",
    },
    {
        "id": "agenttesla",
        "name": "AgentTesla",
        "match": ("AgentTesla", "AgentTesla-like stealer"),
        "what": ".NET keylogger and credential stealer sold as a service: browsers, mail and FTP clients, VPNs, "
                "clipboard and screenshots, sent out by SMTP, FTP or Telegram.",
        "arrives": "Invoice and shipping phishing with archives or scripts that run a .NET crypter (often three "
                   "layers) before the stealer.",
        "reads": ["the exfiltration channel: SMTP server, port, account and recipient; FTP; Telegram bot token and "
                  "chat ID", "settings decrypted statically by the .NET analysis when the strings are encrypted"],
        "next": "Report the mailbox / bot to its provider; hunt the SMTP server and the account on mail gateways.",
        "limits": "Strings encrypted with a custom scheme in a stealer that is still crypted: memory dump.",
    },
    {
        "id": "darkgate",
        "name": "DarkGate",
        "match": ("DarkGate",),
        "what": "Loader and RAT sold as a service (AutoIt-based): hidden VNC, credential theft, crypto mining, "
                "and the delivery of ransomware and other payloads.",
        "arrives": "MSI or VBS / LNK chains that drop AutoIt and a compiled script; Teams and email phishing.",
        "reads": ["the configuration (XOR + base64 with the builder's own alphabet) when it is in the clear",
                  "C2 URLs and port, campaign"],
        "next": "Hunt the C2 URLs and the AutoIt / script pair on the endpoints.",
        "limits": "Usually not unpacked statically (MSI / AutoIt): read the AutoIt script or a memory dump.",
    },
    {
        "id": "darkcloud",
        "name": "DarkCloud",
        "match": ("DarkCloud",),
        "what": "Visual Basic 6 stealer sold as a builder: browser passwords and cards, mail and FTP clients, "
                "keystrokes, clipboard and screenshots, sent out by Telegram, SMTP, FTP or a web panel.",
        "arrives": "Invoice phishing with a script (JS / VBS / PowerShell) that runs a .NET injector, often "
                   "protected with ConfuserEx, which hollows a process with the VB6 stealer.",
        "reads": ["the exfiltration channels from the VB6 string constants: Telegram bot token and chat id, SMTP "
                  "server / port / SSL / account / recipient, FTP, the panel URL",
                  "which channels the buyer left off (the builder's placeholders)",
                  "strings encrypted with RC4 and a key per string", "version, build ID, install path, the VB "
                  "project path of the author, what it steals"],
        "next": "Report the Telegram bot / mailbox to its provider; hunt the token, the SMTP account and the install "
                "path (…\\Templates\\<name>.exe + RunOnce) on the endpoints.",
        "limits": "The stealer must be reached (the injector's payload decoded); another string scheme: memory dump.",
    },
    {
        "id": "metasploit",
        "name": "Metasploit / Meterpreter",
        "match": ("Metasploit / Meterpreter", "Metasploit-style stager", "Metasploit payload (exec)"),
        "what": "Open-source exploitation framework; its stagers fetch the Meterpreter payload, its single payloads "
                "run one command.",
        "arrives": "msfvenom output in a script (psh-cmd, VBA, HTA), an EXE template, raw shellcode, or behind an "
                   "encoder (shikata_ga_nai, x64/xor).",
        "reads": ["stager LHOST / LPORT, transport and URI (the URI checksum), from the block_api shapes",
                  "encoder stubs decoded by emulation (no OS, no network)", "the command of an exec payload"],
        "next": "Hunt the LHOST:LPORT; an exec payload tells exactly what it ran (accounts added, downloads).",
        "limits": "The full Meterpreter (stage 2) behind a custom encrypted loader: memory dump.",
    },
    {
        "id": "go",
        "name": "Go implants (Sliver, Merlin, Mythic…)",
        "match": ("Sliver", "Merlin", "Mythic (Go agent)", "Go implant"),
        "what": "Open-source C2 frameworks written in Go, used by red teams and intrusion sets alike.",
        "arrives": "A standalone Go binary for Windows, Linux or macOS, often obfuscated with Garble.",
        "reads": ["the framework from its packages, functions and strings (compatible / probable / confirmed)",
                  "C2 endpoints only with provenance (the function they come from); Go version and module"],
        "next": "Hunt the endpoints; the module path and build settings link builds of the same operator.",
        "limits": "Sliver under Garble and its encrypted configuration: not read yet; endpoints built at run time "
                  "are not in the file.",
    },
    {
        "id": "stealc",
        "name": "StealC",
        "match": ("StealC",),
        "what": "Native infostealer sold as a service: browsers, wallets, messengers, files; downloads its DLLs "
                "and grabber rules from the C2.",
        "arrives": "Cracked-software and fake-download sites, loader chains.",
        "reads": ["its strings decrypted statically (base64 + RC4 with a key string of the binary)",
                  "the C2 host and its gate (/<16 hex>.php)"],
        "next": "Hunt the gate URL; the RC4 key links samples of the same build.",
        "limits": "What it steals comes from the gate at check-in, not from the file.",
    },
    {
        "id": "vidar",
        "name": "Vidar",
        "match": ("Vidar",),
        "what": "Native infostealer (Arkei lineage) sold as a service; reads its C2 from a dead drop.",
        "arrives": "Malvertising, fake downloads and loaders.",
        "reads": ["its strings decrypted statically (base64 + RC4 with a key string of the binary)",
                  "the dead drops: Telegram channel and Steam profile whose description / name holds the C2"],
        "next": "Open the dead drop with a network check (behind the proxy) to see the current C2; report the "
                "profile / channel.",
        "limits": "The C2 itself is not in the file; older builds with other string protection give nothing.",
    },
    {
        "id": "lumma",
        "name": "Lumma Stealer",
        "match": ("Lumma Stealer", "Lumma-like stealer"),
        "what": "Native infostealer sold as a service (LummaC2), the most common one in 2024–2025: browsers, "
                "wallets, 2FA extensions, files.",
        "arrives": "Fake CAPTCHA pages (copy-paste PowerShell), cracked software, malvertising, loaders.",
        "reads": ["each C2 domain (base64 with its own 32-byte XOR key in front)",
                  "the Steam profile / Telegram channel it falls back to; request fields and user agent as traces"],
        "next": "Hunt the domains (they rotate often) and the dead drop.",
        "limits": "Builds that moved the domains to ChaCha20 or flatten their control flow give traces only: "
                  "memory dump.",
    },
    {
        "id": "bruteratel",
        "name": "Brute Ratel C4",
        "match": ("Brute Ratel C4 (badger)",),
        "what": "Commercial adversary-simulation framework (its agent is the *badger*); leaked builds are used by "
                "intrusion sets.",
        "arrives": "ISO / LNK / DLL side-loading chains that load the badger shellcode in memory.",
        "reads": ["the configuration (base64 + RC4; the builder's default key is tried first, then the "
                  "binary's strings)", "C2 hosts and port, URIs, user agent"],
        "next": "Hunt the C2 and the URIs; a non-default key links badgers of the same operator.",
        "limits": "A badger encrypted again by its loader has to be decrypted first.",
    },
    {
        "id": "havoc",
        "name": "Havoc (Demon)",
        "match": ("Havoc (Demon)",),
        "what": "Open-source C2 framework; its C agent, *Demon*, is used by red teams and intrusion sets.",
        "arrives": "Shellcode loaders, DLL side-loading and script chains.",
        "reads": ["the Demon's configuration buffer: sleep / jitter, allocation and execution methods, the spawn-to "
                  "processes, kill date, working hours", "HTTP method, hosts and ports, TLS, user agent, headers, URIs, proxy"],
        "next": "Hunt the hosts, URIs and user agent; look for the spawn-to processes started without arguments.",
        "limits": "Builds that encrypt the buffer and the Go agent (Havoc-Go) are not read yet.",
    },
    {
        "id": "discord",
        "name": "Discord-webhook grabbers",
        "match": ("Discord-webhook stealer", "Discord webhook"),
        "what": "Small stealers and token grabbers (often Python or .NET, from public repositories) that send what "
                "they take to a Discord webhook.",
        "arrives": "Fake games, cheats and tools shared on Discord and file-sharing sites.",
        "reads": ["the webhook URL (the exfiltration channel) and the stealer traits next to it"],
        "next": "Report the webhook to Discord (it can be deleted); hunt the URL in proxy logs.",
        "limits": "A webhook alone is not malicious: the traits around it decide.",
    },
    {
        "id": "pure",
        "name": "Pure family (PureCrypter / PureLogs / PureHVNC / PureRAT)",
        "match": ("Pure family ",),
        "what": "A .NET malware suite from one seller: a crypter / loader, a stealer, a hidden-VNC RAT and a RAT.",
        "arrives": "Phishing and loader chains; PureCrypter often carries other families.",
        "reads": ["the settings: protobuf, GZip-compressed and base64 in the assembly's strings, read with a "
                  "generic protobuf reader", "C2 host and port; the member of the family when it names itself"],
        "next": "Hunt the host:port; compare the protobuf fields between samples of a campaign.",
        "limits": "Field meanings beyond host and port are shown by number until real samples confirm them; "
                  "obfuscated builds need the .NET string decryption first.",
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
