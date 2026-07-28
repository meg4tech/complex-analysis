# Phase 1 Checkpoint — jsmith / MEGLAB Intrusion (incident date 2026-07-18)

**Checkpoint written:** 2026-07-29
**Sources analyzed to date:** `logs/sysmon.json` (6 events) → `analysis/endpoint.md`; `logs/azure.json` (6 records) → `analysis/cloud.md`; cross-source → `analysis/correlation.md`
**Data caveat carried forward:** both logs are synthetic/lab data with analyst `description` fields and pre-baked ATT&CK tags. All judgments below were re-derived from structured fields (timestamps, IPs, parent/child, auth flags); embedded tags were treated as hints, never as evidence.

---

## 0. Correction to prior session notes

A pre-checkpoint session note recorded **"browser remote debugging port `:9222`"** as a key IOC and **"cookie theft via browser remote debugging port"** as the confirmed technique. **Neither is supported by any artifact in this repository.** A case-insensitive search for `9222|debug|remote-debugging|devtools` across `logs/` and `analysis/` returns zero matches.

The actual, evidenced mechanism is **direct file copy of Chrome's cookie store**:

```
cmd.exe /c copy "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies" %TEMP%\c.db
```

Do not pivot on `:9222`. It appears to be a transcription artifact and would send hunting queries in the wrong direction. The correct endpoint-side hunt signature is *non-browser process reading the Chrome `Network\Cookies` SQLite file*.

---

## 1. Current Understanding of the Attack

A single, coherent intrusion running across two tracks — endpoint and cloud — joined by one stolen session token and one shared attacker IP.

**One-paragraph narrative:** On 2026-07-18, jsmith signed into Entra ID normally from Edinburgh with MFA at 09:14. At 11:02:15 an unsigned binary named `update_report.exe` executed silently from `%TEMP%` with **chrome.exe as its parent**. Over the next 55 seconds it copied Chrome's session-cookie database to a staging file, exfiltrated it to `185.220.101.47:443`, and deleted the staging file. **76 seconds after the endpoint activity ended**, that *same IP* produced a **non-interactive, single-factor** Entra sign-in for jsmith carrying `sessionId: sess_9f2a-copied` — the stolen token replayed, bypassing MFA entirely. Within seven minutes the attacker created a service principal (`sp-datasync-prod`), granted it the `Mail.Read` Graph role, and signed that SP in directly — establishing persistence that is immune to a jsmith password reset or session revocation. The real jsmith signed in normally again at 11:20:55, apparently unaware.

**Why this is one operation and not two coincidental alerts:** the token-theft → token-replay sequence is tightly time-bound (76s) and both ends terminate on the same IP. The endpoint telemetry explains *how the cookie was stolen*; the cloud telemetry explains *what was done with it*. Neither source alone proves the intrusion; together they are mutually corroborating.

### Dual-track timeline (all UTC, 2026-07-18)

| Time | Track | Event |
|---|---|---|
| 09:12:03 | Endpoint | Chrome launched normally by `explorer.exe` |
| 09:14:47 | Endpoint | Chrome → `20.190.128.14:443` (Microsoft login) |
| 09:14:52 | Cloud | jsmith sign-in, **MFA satisfied**, Edinburgh GB — **baseline** |
| *~1h47m* | — | *no telemetry in either source* |
| 11:02:15 | Endpoint | `update_report.exe -silent` from `%TEMP%`, parent = chrome.exe — **foothold** |
| 11:02:19 | Endpoint | `cmd.exe` copies Chrome `Cookies` DB → `%TEMP%\c.db` — **theft** |
| 11:03:02 | Endpoint | `update_report.exe` → `185.220.101.47:443` — **exfil** |
| 11:03:10 | Endpoint | `cmd.exe` deletes `c.db` — **anti-forensics** |
| **+76s** | **PIVOT** | **← endpoint track ends, cloud track begins** |
| 11:04:18 | Cloud | jsmith sign-in from `185.220.101.47`, **non-interactive, single-factor**, `sess_9f2a-copied` — **pass-the-cookie** |
| 11:07:41 | Cloud | Service principal `sp-datasync-prod` created (same IP) |
| 11:09:03 | Cloud | `Mail.Read` Graph role granted to that SP |
| 11:11:29 | Cloud | `sp-datasync-prod` signs in via Graph — **persistence live** |
| 11:20:55 | Cloud | jsmith interactive + MFA from Edinburgh `51.140.22.9` — **real user, unaware** |

---

## 2. Confirmed Findings (with evidence)

### F1 — A real intrusion occurred; this is not a false positive
**Evidence:** `185.220.101.47` appears as the exfil *destination* in Sysmon EventID 3 at 11:03:02 and as the *source* of the Entra sign-in at 11:04:18 plus both audit events and the SP sign-in. Two independent telemetry systems, one attacker IP, 76 seconds apart. Independent corroboration across sources is what elevates this above "two suspicious alerts."

### F2 — Session-cookie theft by a commodity infostealer
**Evidence:** Sysmon EventID 1 at 11:02:19 — `cmd.exe /c copy "%LOCALAPPDATA%\...\Default\Network\Cookies" %TEMP%\c.db`, parent `update_report.exe`. The target is the *actual* Chrome cookie store, named precisely; this is not generic file collection. Full chain (execute → steal → exfil → delete) completes in **55 seconds** with no interactive pacing → automated malware, not hands-on-keyboard.
**ATT&CK:** T1539 (high confidence, independently derived).

### F3 — The endpoint→cloud pivot was MFA bypass via replayed session token
**Evidence:** three structural fields in the 11:04:18 sign-in record align exactly with a replayed cookie and cannot be explained by a live user typing credentials:
- `authenticationRequirement: singleFactorAuthentication` — a downgrade from jsmith's MFA baseline
- `isInteractive: false` — a fresh session from a new hostile IP with no interactive auth
- `sessionId: sess_9f2a-copied`

This is the single most important conclusion in the case: **the endpoint cookie theft and the cloud MFA bypass are the same token changing hands.**
**ATT&CK:** T1550.004 (high confidence).

### F4 — Cloud persistence was established and verified working by the attacker
**Evidence:** Entra AuditLogs — `Add service principal` (`sp-datasync-prod`) at 11:07:41, `Add app role assignment` (`Mail.Read`) at 11:09:03, both from `185.220.101.47`; then SignInLog showing `sp-datasync-prod` authenticating via Microsoft Graph at 11:11:29 from the same IP. The attacker did not merely ride the revocable stolen session — they immediately built an identity outside jsmith's MFA/CA scope and **tested it**.
**ATT&CK:** T1136.003, T1078.004 (high confidence).

### F5 — jsmith is a victim, not the actor
**Evidence:** the endpoint proves the session material was stolen minutes before the cloud actions. Therefore the audit log's `Initiated By: jsmith@meglab.onmicrosoft.com` at 11:07/11:09 is **misleading attribution** — the actions are jsmith-attributed but attacker-driven. The real jsmith reappears at 11:20:55 with full MFA from normal geography. Any response action must not treat jsmith as an insider threat.

### F6 — Anti-forensic intent
**Evidence:** `cmd.exe /c del %TEMP%\c.db` at 11:03:10 — 8.6 seconds after successful exfil, 52 seconds after staging. Timing tied to exfil completion rather than process exit indicates deliberate cleanup, not routine temp hygiene.
**ATT&CK:** T1070.004 (high confidence).

---

## 3. Hypotheses and Confidence Levels

| # | Hypothesis | Confidence | Basis / what would move it |
|---|---|---|---|
| H1 | Initial access was a browser-delivered payload (phishing link or drive-by download) | **Moderate** | Inferred *only* from chrome.exe being the parent of `update_report.exe`. **No delivery event exists in either log** — no email, no URL, no download. The parent-child link proves the browser spawned it; it does not prove how the user was induced. → email/proxy logs |
| H2 | `185.220.101.47` is Tor / anonymized attacker infrastructure | **Moderate** | `185.220.101.0/24` is a widely known Tor exit block and the cloud log self-labels the location "Multiple VPN Exit Nodes." Not verified against a live reputation source in this offline pass. → IP reputation lookup |
| H3 | The exfiltrated `c.db` specifically contained the token replayed at 11:04:18 | **Moderate-High** | Timing (76s) and content (the Chrome cookie store) make it near-certain, but there is no byte-count or payload data in EventID 3 — the link is circumstantial, not proven. → full EDR/network capture |
| H4 | `Mail.Read` was granted as an **application** (not delegated) permission, i.e. **tenant-wide** mailbox read | **Moderate** | The audit record shows the role name but not the consent type. If application-scoped, blast radius is every mailbox in the tenant, not just jsmith's. This single unknown drives the entire impact assessment. → Graph app-role consent details |
| H5 | The objective is bulk email collection (T1114) | **Low — speculative** | Inferred from the *capability established*, never observed being used. No mail-read activity appears in any available log. → Unified Audit Log |
| H6 | A client secret or certificate was added to `sp-datasync-prod` | **Unconfirmed** | Determines whether persistence is genuinely durable. Also resolves the open T1098.001-vs-T1098.003 tagging dispute raised in `cloud.md`. → SP credential audit |
| H7 | Blast radius is limited to jsmith / MEGLAB-WIN11A | **Unconfirmed — no evidence either way** | One host, one user in the available data. Absence of other victims in a 12-record export is not evidence of absence. → environment-wide hunt on the IOC set |

### Open question carried forward from Phase 1
> **How did initial access occur?**

Still unresolved and it is **the** priority gap. What we know: at 11:02:15 chrome.exe spawned `update_report.exe` from `%TEMP%`. What we do not know: whether that was a phishing email link, a drive-by/malvertising download, a compromised legitimate site, or a fake-update lure (the filename suggests the last). The ~1h47m telemetry gap between 09:14:47 and 11:02:15 is where the delivery happened, and **neither log covers it**. This cannot be closed with the data currently in hand.

---

## 4. What We Need to Investigate Next

**Priority 1 — close the initial-access gap (H1)**
1. **Email security / secure email gateway logs** for jsmith, 09:14–11:02 window — message with link or attachment.
2. **Web proxy / DNS / URL filtering logs** for MEGLAB-WIN11A across the same 1h47m gap — the download URL for `update_report.exe`. This is the single highest-value missing source.
3. **Sysmon EventID 11 (file create)** and **EventID 22 (DNS query)** — the full Sysmon set, not the 6-event excerpt (only IDs 1 and 3 present). File-create shows the payload landing on disk; DNS shows what was resolved.

**Priority 2 — determine actual impact (H4, H5)**
4. **Microsoft Graph / Unified Audit Log** — did `sp-datasync-prod` ever exercise `Mail.Read`? Confirms or eliminates T1114 and converts "capability established" into a measured data-loss figure.
5. **App role assignment consent type** — application vs. delegated on the 11:09:03 grant. Decides whether this is a one-mailbox incident or a tenant-wide one.

**Priority 3 — determine persistence durability (H6)**
6. **Service principal credential audit** for `sp-datasync-prod` — any secret or certificate added. Drives whether SP deletion alone is sufficient remediation.
7. **Entra ID Risk Detections / Identity Protection** — did Microsoft independently flag 11:04:18 as anonymous-IP / token-replay / unfamiliar-properties? Independent corroboration of F3.

**Priority 4 — scope the blast radius (H7)**
8. **Full SHA256 for `update_report.exe`** from the EDR console (truncated to `7C3E9D...` in source) → hash-reputation lookup and environment-wide sweep.
9. **Network flow / firewall logs, whole environment** — any other host contacting `185.220.101.47` or related infrastructure.
10. **Conditional Access / session-revocation logs** — was anything auto-remediated after 11:03? Is MEGLAB-WIN11A Entra-registered/compliant, and how did a replayed cookie from unmanaged infrastructure pass CA?

**Hunt signature note:** search for *non-browser processes accessing* `...\Google\Chrome\User Data\*\Network\Cookies` (and the Edge/Firefox equivalents). Do **not** hunt on `:9222` — see §0.

---

## 5. Consolidated IOCs (Phase 1)

| Type | Indicator | Notes |
|---|---|---|
| IP | `185.220.101.47` | Attacker infra — exfil dest **and** cloud sign-in source. Highest-value pivot. |
| File | `update_report.exe` (SHA256 `7C3E9D...`, truncated) | Dropper/infostealer — pull full hash from EDR |
| File | `%TEMP%\c.db` | Staged stolen cookie DB (deleted 11:03:10) |
| File | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies` | Theft target |
| Identity | `jsmith@meglab.onmicrosoft.com` / `MEGLAB\jsmith` | Compromised user — **victim** |
| SP | `sp-datasync-prod` | Attacker-created persistence identity |
| Perm | `Mail.Read` (Graph) | Granted to rogue SP; consent type unknown |
| Session | `sess_9f2a-copied` | Replayed session identifier |
| Host | `MEGLAB-WIN11A` (`10.10.5.42`) | Compromised endpoint |
| Baseline (benign) | `20.190.128.14`, `51.140.22.9` | Legitimate Microsoft / Edinburgh egress — for comparison, not blocking |

## 6. ATT&CK Summary

Initial Access: T1204.002 *(inferred)* · Execution: T1059.003 · Defense Evasion: T1036.005, T1070.004 · Credential Access: T1539 · Exfiltration: T1041 · C2: T1071.001 · Cloud pivot: T1550.004 · Persistence: T1136.003, T1098.001/T1098.003 *(disputed — see `cloud.md` §4)* · Valid Accounts: T1078.004 · Collection: T1114 *(speculative, unconfirmed)*
