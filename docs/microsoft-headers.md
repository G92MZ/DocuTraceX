# Microsoft 365 / Exchange Online headers — inventory

What each header gives a DFIR analyst, how far it can be trusted, and what
DocuTraceX does with it. **Implemented** = decoded by `docutracex/msheaders.py`
(shown in the email view → *Authentication* → *Microsoft 365*) and, where a
rule is named, used by the email rules (`docutracex/rules/email/core.yml`).

**Sources**:
- [MS-AS] Microsoft Learn, *Anti-spam message headers in Microsoft 365*. It covers `X-Forefront-Antispam-Report`, `X-Microsoft-Antispam` and `Authentication-Results` / compauth.
- [EXO-HYB] Exchange Team blog, *Demystifying hybrid mail flow: when is a message internal?* It covers AuthAs and MessageDirectionality.
- *Undocumented* means Microsoft does not publish the meaning. The values are shown raw and are never used as a verdict.

**Trust model.** Any header can be written by whoever sends the message. Exchange Online strips the `X-MS-Exchange-Organization-*` headers from mail that comes from outside and stamps its own. The recipient's EOP adds `X-Forefront-Antispam-Report`, `X-Microsoft-Antispam` and `Authentication-Results` **on top**. So the **topmost** copy is the receiving tenant's; a lower copy came with the message, either from another tenant on the path or forged. DocuTraceX reads the topmost copy and notes when more copies exist.

## Tenants and organisation

| Header | Information | DFIR use | Manipulation | Correlations | Findings | IOCs | Priority | Status |
|---|---|---|---|---|---|---|---|---|
| `X-MS-Exchange-CrossTenant-Id` | GUID of a Microsoft 365 tenant the message passed through | Attribution: which organisation's tenant sent it (resolved with AZMap) | A sender can add one; the receiving tenant stamps its own | Grouped with CrossTenant-AuthAs / AuthSource / FromEntityHeader / OriginalArrivalTime / Network-Message-Id, one block per tenant | `tenant_sender_domain_unrelated` (high, 40: not a current domain of the tenant, or removed from it); `tenant_sender_lookalike` (high, 50: the sender's domain imitates yours / a brand, Managed in the tenant or not); `tenant_holds_lookalikes` (high, 25); `tenant_domain_sprawl` (medium, 10: many unrelated and / or removed domains) | Tenant ID (markable) | High | **Implemented** + AZMap |
| `X-MS-Exchange-CrossTenant-AuthAs` | `Internal` (authenticated in that tenant) / `Anonymous` (came in from outside) | Tells the **sender's** tenant (Internal) from the **receiving** one (Anonymous) | As above | CrossTenant-Id of the same block | `ms_own_domain_from_internet` (via the receiving block) | — | High | **Implemented** |
| `X-MS-Exchange-CrossTenant-AuthSource` | Server that authenticated it in that tenant | The sender's mailbox server (EXO host) | As above | Received chain | — | Host | Low | Decoded |
| `X-MS-Exchange-CrossTenant-FromEntityHeader` | `Hosted` (from a mailbox in a tenant) / `Internet` | Mail from the Internet claiming an internal domain | As above | AuthAs | `ms_own_domain_from_internet` | — | Medium | **Implemented** |
| `X-MS-Exchange-CrossTenant-OriginalArrivalTime` | When the tenant received it | Timeline; compare with Date / Received | Sender-side copy forgeable | Date, Received, Chain | `ms_date_vs_arrival` (Date > 1 h after arrival, or > 7 days before) | — | Medium | **Implemented** |
| `X-MS-Exchange-CrossTenant-Network-Message-Id` / `X-MS-Exchange-Organization-Network-Message-Id` | Internal message ID of the tenant | Pivot into **Message trace** / Defender Explorer of the tenant | — | Message-ID | — | ID (markable) | High (for the tenant's own SOC) | Decoded |
| `X-MS-Exchange-CrossTenant-MailboxType`, `-UserPrincipalName` | Sender mailbox type / UPN (when present) | Real account behind a display name | Sender-side | From, Sender | — | Email | Medium | Decoded |
| `X-OriginatorOrg` | The originating organisation's primary domain | Attribution; compare with From | Forgeable from outside | From, CrossTenant-Id | `ms_originator_org_mismatch` (unless the From domain is one of the tenant's, per AZMap) | Domain | Medium | **Implemented** |
| `X-EOPAttributedMessage`, `X-EOPTenantAttributedMessage` | Attribution of the message to a tenant (`<tenant>:0`) | Which tenant EOP charged it to | — | CrossTenant-Id | — | Tenant ID | Low | Decoded |

## Direction and authentication inside Exchange

| Header | Information | DFIR use | Manipulation | Correlations | Findings | IOCs | Priority | Status |
|---|---|---|---|---|---|---|---|---|
| `X-MS-Exchange-Organization-AuthAs` | `Internal` (authenticated mailbox, SMTP AUTH, connector trusted as internal) / `Anonymous` (Internet, relay, Pickup) [EXO-HYB] | Spoofing of your own domain: From = your domain but `Anonymous` | Stripped and re-stamped by EXO on inbound | From, own domains (Settings) | `ms_own_domain_from_internet` | — | High | **Implemented** |
| `X-MS-Exchange-Organization-AuthSource`, `-AuthMechanism` | Which server / mechanism authenticated it (`10` appears for "Externally Secured" connectors) [EXO-HYB] | Misconfigured connectors treating Internet mail as internal | Re-stamped | AuthAs | — | Host | Low | Decoded |
| `X-MS-Exchange-Organization-MessageDirectionality` | `Incoming` / `Originating` [EXO-HYB] | Internal mail vs Internet | Re-stamped | AuthAs, DIR | — | — | Medium | Decoded |
| `X-MS-Exchange-ExternalOriginalInternetSender` | Original Internet sender when *Enhanced Filtering* is on | The real source behind a gateway | — | CIP | — | Email / IP | Medium | Decoded |
| `X-MS-Exchange-Organization-SCL` | Spam confidence level | On-premises / hybrid Junk routing **only**: not the cloud's verdict [MS-AS] | — | SFV, CAT | — | — | Low | Decoded |

## Anti-spam / anti-phishing verdict

| Header | Information | DFIR use | Manipulation | Correlations | Findings | IOCs | Priority | Status |
|---|---|---|---|---|---|---|---|---|
| `X-Forefront-Antispam-Report` **CAT** | Policy applied: PHSH, HPHSH, SPOOF, BIMP/DIMP/GIMP/UIMP (impersonation), MALW, AMP, FTBP, SAP, SPM, HSPM, BULK, INTOS, OSPM [MS-AS] | Microsoft's own classification | Only the topmost copy is the receiver's | SFV, SFTY, compauth | `ms_classified_phishing`, `ms_classified_malware` (counts for *malicious*) | — | High | **Implemented** |
| … **SFV** | NSPM, SPM, SKA, SKB, SKI, SKN, SKQ, SKS, SFE, BLK [MS-AS] | Spam verdict, and **why filtering was skipped** (allow lists, transport rules) | As above | IPV | `ms_spam_verdict`, `ms_filter_bypassed` | — | High | **Implemented** |
| … **SFTY** | 9.19 domain impersonation, 9.20 user impersonation, 9.25 first contact [MS-AS] | Impersonation of protected users / domains | As above | CAT | `ms_impersonation_tip`, `ms_first_contact` (info) | — | High | **Implemented** |
| … **CIP** | Connecting IP | The sending server | As above | Received, PTR, CTRY | — | **IPv4/IPv6** | High | **Implemented** (IOC) |
| … **CTRY**, **LANG** | Country of the connecting IP; language of the message | Context (a Spanish supplier sending from elsewhere…) | As above | CIP | `ms_country_not_allowed` (allowed-country list in Settings) | — | Medium | **Implemented** |
| … **PTR**, **H** | Reverse DNS of CIP; HELO/EHLO string | Sending infrastructure | As above | CIP, Received | — | **Domain** | Medium | **Implemented** (IOC) |
| … **IPV**, **DIR**, **SRV**, **SFS** | IP reputation (CAL = allow list, NLI), direction (INB/OUT/INT), BULK, internal rule IDs (diagnostic) [MS-AS] | Allow-listed source; direction | As above | SFV | `ms_filter_bypassed` (IPV:CAL) | — | Medium | Decoded |
| `X-Microsoft-Antispam` **BCL** / PCL | Bulk complaint level (higher = more complaints); PCL undocumented [MS-AS] | Bulk vs targeted | As above | CAT:BULK | `ms_bulk_high` (BCL ≥ 7) | — | Low | **Implemented** |
| `Authentication-Results` **compauth** + reason | Composite authentication pass / fail / softpass / none with a 3-digit reason (000, 001, 010, 1xx, 601, 905…) [MS-AS] | *Why* Microsoft judged the From domain authentic or not (intra-org spoofing = 010 / 601) | Topmost copy only | SPF / DKIM / DMARC | `ms_compauth_fail` | — | High | **Implemented** |
| … **action** | DMARC action: oreject, pct.quarantine, pct.reject, permerror, temperror [MS-AS] | DMARC enforced or not | As above | DMARC policy | (feeds `dmarc_fail_policy_none`) | — | Medium | Decoded |
| `X-Microsoft-Antispam-Mailbox-Delivery` | `ucf`, `jmr`, `auth`, `dest` (I/J), `OFR`, `RF`… | Where it was delivered (dest:J is commonly read as Junk) | — | SFV | — | — | Low | Decoded, **undocumented** |
| `X-MS-Exchange-AtpMessageProperties` | Defender features applied (SA = Safe Attachments, SL = Safe Links) | Whether Defender scanned it | — | CAT:SAP | — | — | Low | Decoded |
| `X-MS-Exchange-EnableFirstContactSafetyTip` | First-contact tip enabled | Context for SFTY 9.25 | — | SFTY | — | — | Low | Decoded |

## Client and transport

| Header | Information | DFIR use | Manipulation | Correlations | Findings | IOCs | Priority | Status |
|---|---|---|---|---|---|---|---|---|
| `X-Originating-IP` | The sender's **client** IP (OWA / Outlook submissions) | The attacker's IP when a mailbox is compromised | Added by the sender's side; forgeable | CIP, Received | (future: geo / reputation) | **IP** | High | **Implemented** (IOC) |
| `X-MS-Has-Attach`, `X-MS-TNEF-Correlator` | Outlook client markers | Message really written in Outlook (vs a mailer faking it) | Trivial to add | X-Mailer | — | — | Low | Listed |
| `X-MS-PublicTrafficType`, `X-MS-TrafficTypeDiagnostic` | Internal traffic classification / diagnostics | Undocumented | — | — | — | — | Low | Listed |
| `X-MS-Office365-Filtering-Correlation-Id` | Correlation ID for Microsoft support | Pivot for the tenant's admins | — | Network-Message-Id | — | ID | Low | Listed |
| `Thread-Topic`, `Thread-Index` | Outlook conversation topic and index (base64: 22-byte header + 5 bytes per reply) | Conversation start (FILETIME) and one 5-byte block per reply ([MS-OXOMSG] 2.2.1.3) | Forgeable | Chain, References, Date | `thread_index_after_date`, `thread_index_new_conversation_reply` | — | Medium | **Implemented** (decoded in Chain and the Microsoft 365 box) |
| `ARC-*` | Authenticated Received Chain (AAR, AMS, AS with cv=none/pass/fail) [MS-AS] | Forwarding that broke SPF/DKIM | Signed | Authentication-Results | ARC-vouched forward = legitimacy signal (existing) | — | Medium | Existing |
