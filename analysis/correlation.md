# Correlated Incident Analysis — jsmith / MEGLAB (2026-07-18)

**Sources correlated:** `analysis/endpoint.md` (Sysmon / MEGLAB-WIN11A) and `analysis/cloud.md` (Entra ID / meglab.onmicrosoft.com)

**Data caveat:** Both source logs are almost certainly synthetic/lab data (they carry embedded analyst-style `description` fields and pre-baked ATT&CK tags that real Sysmon/Entra telemetry does not produce). Each source analysis independently re-derived its judgments from structured fields rather than parroting those tags; this correlation builds only on those independently-verified findings. Confirmed as training data by the user.

---

## 1. Timeline Alignment

All times UTC, 2026-07-18. **E** = endpoint/Sysmon, **C** = cloud/Entra ID.

| Time (UTC) | Src | Event |
|---|---|---|
| 09:12:03 | E | Chrome launched normally by `explorer.exe` on MEGLAB-WIN11A |
| 09:14:47 | E | Chrome → `20.190.128.14:443` (Microsoft login) |
| 09:14:52 | C | jsmith interactive sign-in, **MFA satisfied**, from `20.190.128.14`, Edinburgh GB — **baseline** |
| *(~1h47m quiet)* | | |
| 11:02:15 | E | `update_report.exe` runs silently from `%TEMP%`, parent = Chrome — **foothold** |
| 11:02:19 | E | `cmd.exe` copies Chrome `Cookies` DB → `%TEMP%\c.db` — **session-token theft** |
| 11:03:02 | E | `update_report.exe` → `185.220.101.47:443` — **exfil** |
| 11:03:10 | E | `cmd.exe` deletes `c.db` — **cleanup** |
| **~76s gap** | | **← the endpoint→cloud pivot happens across this gap** |
| 11:04:18 | C | jsmith sign-in from `185.220.101.47`, **non-interactive, single-factor**, `sessionId: sess_9f2a-copied` — **pass-the-cookie** |
| 11:07:41 | C | jsmith identity (same IP) creates service principal `sp-datasync-prod` |
| 11:09:03 | C | grants `sp-datasync-prod` the `Mail.Read` Graph role |
| 11:11:29 | C | `sp-datasync-prod` signs in via Graph, same IP — **MFA/CA bypass persistence active** |
| 11:20:55 | C | jsmith interactive sign-in, MFA, Edinburgh `51.140.22.9` — **real user, unaware** |

The two sources interlock cleanly: the endpoint story ends at 11:03:10 (exfil + cleanup) and the cloud story begins 68 seconds later at 11:04:18. The endpoint tells you *how the cookie was stolen*; the cloud tells you *what was done with it*.

## 2. User Correlation

Only one identity spans both sources — and it's the crux of the case:

- **Endpoint:** `MEGLAB\jsmith` — the logged-in Windows user whose Chrome cookie store was copied and exfiltrated. The user here is a *victim*; the malicious actions were performed by `update_report.exe` running in their session, not by deliberate user action.
- **Cloud:** `jsmith@meglab.onmicrosoft.com` — the Entra identity that then signs in from the attacker IP and performs the SP creation + permission grant. The actor here is the *attacker wearing jsmith's stolen session*, not jsmith.

Same human, two naming conventions (`DOMAIN\user` vs UPN) — normalize on `jsmith`. The critical insight from correlation: **the "jsmith" performing cloud actions at 11:04–11:09 is not the real jsmith.** The endpoint data proves the session material was stolen minutes earlier, so the cloud audit log's "Initiated By: jsmith" is misleading — it's attributed to jsmith but driven by the attacker. The real jsmith reappears legitimately at 11:20:55 with full MFA from their normal geography.

## 3. IP Correlation

Two IPs appear in **both** sources — this is the backbone of the correlation:

| IP | Endpoint role | Cloud role | Verdict |
|---|---|---|---|
| **`185.220.101.47`** | Exfil destination (11:03:02, from `update_report.exe`) | Source of the pass-the-cookie sign-in + both audit events + SP sign-in (11:04–11:11) | **Attacker infrastructure.** The stolen cookie leaves the endpoint to this IP, then the *same IP* logs in with it 76s later. Tor exit-node range. Single highest-value pivot IOC. |
| **`20.190.128.14`** | Chrome → this IP at 09:14:47 (login.microsoftonline.com) | jsmith's baseline MFA sign-in at 09:14:52 | **Legitimate Microsoft.** The 5-second match confirms clock alignment between sources and anchors the known-good baseline. |

`51.140.22.9` (cloud only, 11:20:55) and internal `10.10.5.42` (endpoint only) don't cross over — the former is the real user's later egress, the latter is the victim host's LAN address.

The `185.220.101.47` overlap is the smoking gun: exfil-out and login-in on the same attacker IP, tightly time-bound, is what turns two separate "suspicious" stories into one confirmed intrusion.

## 4. Attack Chain

**Initial access — partially inferred.** The earliest malicious event is `update_report.exe` executing at 11:02:15 with Chrome as its parent. That parent-child link points to a browser-delivered payload (malicious download or drive-by), but **neither log captures the delivery** — no email, no URL, no download event. So "phishing/malicious download" is a reasonable inference from the process lineage, not something proven by the data. (ATT&CK T1204 User Execution is embedded in the log but the *how* is unconfirmed.)

**Actions on endpoint (11:02:15 → 11:03:10, ~55s, fully automated):**
1. `update_report.exe` (masquerading as an updater, unsigned, from `%TEMP%`) executes — T1204.002 / T1036.005
2. Spawns `cmd.exe` to copy Chrome's `Cookies` SQLite DB to `%TEMP%\c.db` — T1539 Steal Web Session Cookie
3. Exfiltrates to `185.220.101.47:443` — T1041
4. Deletes the staging file — T1070.004

The 55-second, hands-off tempo indicates a commodity infostealer, not interactive operator activity on the box.

**Pivot to cloud (the 76-second gap):** The stolen Chrome cookies contained a valid Entra session/refresh token. The attacker replayed it from their own infrastructure — this is why the 11:04:18 sign-in is **non-interactive and single-factor**: no fresh credential entry, no MFA challenge, because a live session token doesn't require them. T1550.004 Web Session Cookie. This is the single most important correlation conclusion: **the endpoint cookie theft and the cloud MFA bypass are the same token changing hands.**

**Actions on cloud → objective (11:04–11:11):** Rather than just riding the (revocable) stolen session, the attacker immediately established durable persistence:
- Created service principal `sp-datasync-prod` (T1136.003) — an app identity outside jsmith's MFA/CA controls
- Granted it `Mail.Read` (Graph) — if application-scoped, that's **tenant-wide mailbox read**, not just jsmith's
- Signed the SP in directly via Graph (T1078.004) — confirming the persistence path works

**Ultimate objective:** Durable, MFA-immune access to mailbox data across the tenant. The SP survives a jsmith password reset or session revocation, and `Mail.Read` is a quiet bulk-email-exfiltration primitive. The likely end goal is email collection/exfil (T1114) — but note **no log in either source shows mail actually being read**, so the objective is inferred from the capability established, not observed being used.

## 5. Confidence Assessment

**High confidence:**
- A real intrusion occurred (not a false positive) — the cross-source `185.220.101.47` linkage and the token-theft→token-replay sequence are mutually corroborating across independent telemetry.
- Mechanism of the endpoint→cloud pivot: stolen browser session cookie replayed for MFA bypass. The `singleFactorAuthentication` + `isInteractive:false` + `sessionId ...-copied` fields align exactly with the endpoint cookie-copy + exfil.
- Cloud persistence was established: SP creation + Mail.Read grant + SP sign-in are directly in the audit/sign-in records.
- The real jsmith was a victim, not the actor, for the 11:04–11:11 activity.

**Moderate confidence:**
- Initial-access vector (phishing/malicious download) — inferred from Chrome-as-parent, not captured.
- `185.220.101.47` as Tor/anonymized infrastructure — consistent with the range and the "Multiple VPN Exit Nodes" label, but not verified against a live reputation source in this offline pass.
- That the exfiltrated `c.db` specifically contained the token used at 11:04 — timing and content make it near-certain, but there's no byte-level proof the cookie file was the payload sent.

**Low confidence / unconfirmed:**
- Whether `Mail.Read` was actually *exercised* to read/exfil mail — capability established, use not observed.
- Whether a client secret/certificate was added to the SP (would determine true persistence durability) — not in this export; also drives the T1098.001-vs-T1098.003 tagging question the cloud analyst raised.
- Blast radius beyond jsmith/MEGLAB-WIN11A — single host, single user in this data; no evidence either way about other victims.

## 6. Gaps — logs that would resolve the uncertainties

- **Email security / proxy / web gateway logs** — to nail down initial access: the phishing email or the URL/download that delivered `update_report.exe`. Biggest gap.
- **Full Sysmon/EDR set** — this export has only 6 events (IDs 1 & 3). DNS (Sysmon 22), file-create (11), and the *full* hash for `update_report.exe` would enable reputation lookup and confirm delivery.
- **Entra ID Risk Detections / Identity Protection** — would show whether Microsoft independently flagged the 11:04 sign-in as anonymous-IP/token-replay/unfamiliar-properties, corroborating the pass-the-cookie call.
- **Microsoft Graph / mailbox audit logs (Unified Audit Log)** — to confirm or rule out whether `sp-datasync-prod` actually used `Mail.Read` to access mailboxes (resolves the objective).
- **Service principal credential audit** — whether a secret/cert was added to the SP (durability of persistence + resolves the ATT&CK sub-technique dispute).
- **Conditional Access / session-revocation logs** — whether anything auto-remediated after 11:03, and whether the device is Entra-registered/compliant (would explain how a cookie from an unmanaged replay passed CA).
- **Network flow/firewall logs** — independent confirmation of the `10.10.5.42 → 185.220.101.47` exfil and any other contact with that IP or related infrastructure across the environment.

---

## Bottom line

Two independent telemetry sources converge on one coherent intrusion — a commodity infostealer stole jsmith's Chrome session cookie and exfiltrated it to `185.220.101.47` (11:02–11:03), and 76 seconds later that same IP replayed the token to bypass MFA and stand up a rogue service principal with tenant-wide `Mail.Read` for durable, MFA-immune persistence (11:04–11:11). The shared IP and the token-theft→token-replay timing are what make this a confirmed correlation rather than two coincidental alerts. The main unknowns are the initial delivery vector and whether the mail-read capability was actually used — both requiring logs we don't have.

## Consolidated IOCs

| Type | Indicator | Notes |
|---|---|---|
| IP | `185.220.101.47` | Attacker infra — exfil dest + cloud sign-in source. Highest-value pivot. |
| File | `update_report.exe` (SHA256 `7C3E9D...`, truncated) | Dropper/infostealer; pull full hash from EDR |
| File | `%TEMP%\c.db` | Staged stolen cookie DB (deleted) |
| File | `%LOCALAPPDATA%\...\Default\Network\Cookies` | Theft target |
| Identity | `jsmith@meglab.onmicrosoft.com` / `MEGLAB\jsmith` | Compromised user (victim) |
| SP | `sp-datasync-prod` | Attacker-created persistence identity |
| Perm | `Mail.Read` (Graph) | Granted to rogue SP |
| Session | `sess_9f2a-copied` | Replayed session identifier |
| Host | `MEGLAB-WIN11A` (`10.10.5.42`) | Compromised endpoint |

## ATT&CK Summary (independently assessed across both sources)

Initial Access: T1204.002 (inferred) · Defense Evasion: T1036.005, T1070.004 · Execution: T1059.003 · Credential Access: T1539 · Exfiltration: T1041 · C2: T1071.001 · Lateral/Cloud pivot: T1550.004 · Persistence: T1136.003, T1098.001/T1098.003 (disputed — see cloud.md) · Valid Accounts: T1078.004 · Collection: T1114 (speculative, unconfirmed)
