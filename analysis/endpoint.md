# EDR Analysis Report — MEGLAB-WIN11A (Sysmon Telemetry)

**Source:** `logs/sysmon.json` (6 events, single host, single user session)

**Caveat on the data itself:** Each record in this file carries a `Description` field containing an analyst-style verdict and, in several cases, an embedded MITRE ATT&CK ID (e.g. "T1204 User Execution", "T1539 Steal Web Session Cookie", "T1041 Exfiltration Over C2 Channel", "T1070.004 File Deletion"). Real Sysmon events do not include a narrative/verdict field — this is clearly synthetic lab data with an answer key baked in. These tags were treated as **unverified metadata, not ground truth**, and each judgment was independently re-derived from the structural facts (parent/child relationship, path, timing, port, IP). Where the independent conclusion agrees with the embedded tag, that's noted explicitly; tags were not simply parroted.

---

## 1. Process Lineage & Execution Analysis (EventID 1)

| Time (UTC) | PID | Image | CommandLine | ParentImage | Hash | Assessment |
|---|---|---|---|---|---|---|
| 09:12:03.221Z | 4412 | `C:\Program Files\Google\Chrome\Application\chrome.exe` | `"chrome.exe" --profile-directory=Default` | `C:\Windows\explorer.exe` | SHA256=9F2A1B... | Normal — legitimate binary path, standard shell-launched browser start. No concern. |
| 11:02:15.554Z | 6820 | `C:\Users\jsmith\AppData\Local\Temp\update_report.exe` | `update_report.exe -silent` | `C:\Program Files\Google\Chrome\Application\chrome.exe` | SHA256=7C3E9D... | **Suspicious.** Executes from a user-writable Temp path, name masquerades as a legitimate updater, `-silent` flag suggests unattended/automated execution rather than a normal user-initiated install, and parent is the browser (classic download-and-run pattern). Binary is not a known-signed vendor path. This is the initial foothold. |
| 11:02:19.117Z | 6902 | `C:\Windows\System32\cmd.exe` | `cmd.exe /c copy "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies" %TEMP%\c.db` | `update_report.exe` | — | **Malicious LOLBin use.** cmd.exe spawned by the dropped binary (not by a user/explorer) to copy Chrome's actual session-cookie SQLite database to a staging file. This is a precise, deliberate target — not generic data collection. |
| 11:03:10.998Z | 6944 | `C:\Windows\System32\cmd.exe` | `cmd.exe /c del %TEMP%\c.db` | `update_report.exe` | — | **Cleanup/anti-forensics.** Same parent deletes the staged file ~52 seconds after it was created, and ~9 seconds after the outbound connection below — consistent with post-exfil cleanup rather than routine temp-file hygiene. |

**Notable anomalies:** unusual parent-child chain browser → Temp EXE → cmd.exe (x2), all under the same PID lineage from `update_report.exe`; execution entirely from `%TEMP%`/`%LOCALAPPDATA%`; no code-signing/hash-reputation data available to confirm legitimacy of `update_report.exe` (hash is truncated in source, `7C3E9D...` — should be pulled in full from the EDR console for hash-reputation lookup).

## 2. Network Connection Analysis (EventID 3)

| Time (UTC) | Process | Source IP | Destination IP | Port | Assessment |
|---|---|---|---|---|---|
| 09:14:47.803Z | chrome.exe | 10.10.5.42 | 20.190.128.14 | 443 | Logged as "login.microsoftonline.com" in the description — Azure/Microsoft-owned IP range is plausible for M365/Entra ID auth traffic. Treat as **likely benign** but should be independently confirmed, since this file itself contains no authoritative IP reputation data. |
| 11:03:02.442Z | update_report.exe | 10.10.5.42 | 185.220.101.47 | 443 | **Highly suspicious.** 185.220.101.0/24 is a widely known Tor exit-node block, not a corporate or SaaS range. Connection originates from the dropped binary (not chrome/system), occurs ~43 seconds after the cookie DB was staged, and precedes the cleanup step by ~9 seconds. Port 443 is used to blend with normal HTTPS traffic. This is the exfil channel. |

No other EventID 3 records exist in the file (only 2 total network events).

## 3. Timeline (chronological)

1. **09:12:03.221Z** — `chrome.exe` launched normally by `explorer.exe` (jsmith interactive session begins).
2. **09:14:47.803Z** — Chrome connects outbound to 20.190.128.14:443 (purportedly Microsoft login).
3. *(~1h47m gap — no telemetry)*
4. **11:02:15.554Z** — `update_report.exe` executes silently from `%TEMP%`, spawned directly by `chrome.exe` — the point of initial compromise/payload execution.
5. **11:02:19.117Z** (+3.9s) — `update_report.exe` spawns `cmd.exe` to copy Chrome's `Cookies` database to `%TEMP%\c.db` — credential/session-token staging.
6. **11:03:02.442Z** (+43.3s) — `update_report.exe` connects to 185.220.101.47:443 — staged data exfiltrated.
7. **11:03:10.998Z** (+8.6s) — `update_report.exe` spawns `cmd.exe` to delete `%TEMP%\c.db` — cleanup.

The entire compromise chain (payload execution → theft → exfil → cleanup) spans **~55 seconds**, indicating fully automated/scripted malware behavior rather than manual hands-on-keyboard activity — consistent with a commodity cookie/session-stealer.

## 4. MITRE ATT&CK Mapping (independent assessment)

| Behavior | Technique | Confidence | Notes on embedded tag |
|---|---|---|---|
| Chrome spawns unsigned Temp EXE with `-silent` flag | **T1204.002** – User Execution: Malicious File | Medium | Log embeds "T1204 User Execution." A file-execution technique fits, but the parent-child link alone doesn't prove *how* the user was induced to run it (no download/phishing-vector event present) — confidence capped at Medium for lack of delivery evidence. |
| `update_report.exe` naming/path disguising it as a legitimate updater | **T1036.005** – Masquerading: Match Legitimate Name or Location | Medium-High | Not tagged in source data — own addition based on filename/path analysis. |
| cmd.exe used to copy/delete files | **T1059.003** – Command and Scripting Interpreter: Windows Command Shell | High | Not tagged in source; independently derived from LOLBin usage pattern (both cmd.exe invocations spawned by malware, not user). |
| Copying Chrome's `Network\Cookies` DB to a staging file | **T1539** – Steal Web Session Cookie | High | Log embeds "T1539" exactly. Independently confirmed — the targeted file path is the actual Chrome cookie store, a precise and well-known technique signature, not generic file copying. |
| Outbound connection to Tor-associated IP immediately after staging | **T1041** – Exfiltration Over C2 Channel | Medium-High | Log embeds "T1041." Independently agree based on timing + destination reputation + process lineage, but note there's no byte-count/payload data in the record to directly confirm the cookie file was what was sent — inference is circumstantial, not proven. |
| Use of HTTPS/443 for C2 | **T1071.001** – Application Layer Protocol: Web Protocols | Medium | Not tagged in source; own addition — standard port chosen to blend with normal traffic. |
| Deletion of staged file post-exfil | **T1070.004** – Indicator Removal: File Deletion | High | Log embeds "T1070.004." Independently agree — timing (immediately after successful exfil) strongly supports anti-forensic intent over routine cleanup. |

## 5. IOCs

**Hashes** (truncated in source — pull full hashes from EDR console before pivoting):
- `SHA256=7C3E9D...` — `update_report.exe` (primary malware IOC)
- `SHA256=9F2A1B...` — `chrome.exe` (legitimate; reference only)

**File paths/names:**
- `C:\Users\jsmith\AppData\Local\Temp\update_report.exe`
- `%TEMP%\c.db` (staged/exfiltrated cookie data)
- `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies` (targeted source file)

**Process names:** `update_report.exe`, `cmd.exe` (x2, PIDs 6902 & 6944), `chrome.exe` (PID 4412, initial parent)

**Network:**
- Host/internal IP: `10.10.5.42`
- `20.190.128.14:443` (claimed login.microsoftonline.com — needs independent validation)
- `185.220.101.47:443` (Tor exit-node range — high-confidence malicious infrastructure)

**Host/User:**
- Hostname: `MEGLAB-WIN11A`
- User: `MEGLAB\jsmith`
- PIDs: 4412, 6820, 6902, 6944

## 6. Open Questions for Correlation (Identity/Cloud logs)

- Does Azure AD show a sign-in for jsmith (or their UPN) at/around **09:14:47Z** matching the `login.microsoftonline.com` connection — and is it a normal, MFA-satisfied, known-device sign-in, or could it itself be attacker-initiated?
- **Critical:** After **11:02:19Z** (cookie theft) and especially after **11:03:02Z** (exfil), does Azure AD show any sign-ins for jsmith using a session/refresh token from an unfamiliar location, unmanaged device, or an IP overlapping with `185.220.101.47` or other Tor/VPN infrastructure — i.e., evidence of "pass-the-cookie" token replay?
- Any Entra ID risk detections ("unfamiliar sign-in properties," "anonymous IP address," impossible travel, token-replay risk) flagged for jsmith's account on 2026-07-18 in this window?
- Is `20.190.128.14` confirmed as a legitimate, tenant-associated Microsoft/Entra IP range, or does it warrant its own scrutiny?
- Any conditional-access enforcement, session revocation, or forced re-auth triggered for jsmith around/after 11:03Z?
- Post-compromise account activity: new OAuth app consents, mailbox forwarding/rule changes, MFA method registration changes, or password resets for jsmith following this window — signs the stolen session was used for account takeover?
- Do any other endpoints/users show sign-ins or connections tied to `185.220.101.47` or the same file hash, suggesting this isn't isolated to MEGLAB-WIN11A?
- Is MEGLAB-WIN11A a registered/compliant device in Entra ID, and could the stolen cookie have been used to bypass device-compliance conditional access from an unmanaged device?
