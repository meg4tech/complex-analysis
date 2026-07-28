# Entra ID Identity Telemetry Investigation Report

**Source:** `logs/azure.json` (6 records: 4 SignInLogs, 2 AuditLogs)

**Note on data quality:** Each record contains an embedded free-text `description` field, and several contain literal MITRE ATT&CK technique IDs (e.g. `T1550.004`, `T1136.003`, `T1098.001`, `T1078.004`). Real Entra ID Sign-in/Audit logs do not natively include narrative descriptions or ATT&CK tags — this is almost certainly lab/exercise metadata rather than authentic telemetry annotation. The structured fields (timestamps, IPs, session flags, auth requirements) were used as the primary evidence; embedded descriptions/tags were treated as hints to verify independently, not as ground truth.

---

## 1. Sign-In Analysis

| Time (UTC) | UPN | IP | Location | Client | CA Status | Auth Req | Interactive | Status |
|---|---|---|---|---|---|---|---|---|
| 09:14:52 | jsmith@meglab.onmicrosoft.com | 20.190.128.14 | Edinburgh, GB | Browser | success | multiFactorAuthentication | (implied true) | success |
| 11:04:18 | jsmith@meglab.onmicrosoft.com | 185.220.101.47 | "Unknown, Multiple VPN Exit Nodes" | Browser | success | **singleFactorAuthentication** | **false** | success |
| 11:11:29 | sp-datasync-prod | 185.220.101.47 | — | Microsoft Graph | (n/a) | (n/a — SP auth) | (n/a) | success |
| 11:20:55 | jsmith@meglab.onmicrosoft.com | 51.140.22.9 | Edinburgh, GB | Browser | success | multiFactorAuthentication | (implied true) | success |

**Findings:**
- **09:14:52Z** — Baseline legitimate sign-in: interactive, MFA satisfied, plausible UK IP/location, standard Browser client.
- **11:04:18Z — Anomalous.** ~110 minutes later, same user authenticates from an IP self-labeled "Multiple VPN Exit Nodes" (185.220.101.0/24 is a range publicly associated with Tor exit infrastructure in threat intel — worth confirming via IP reputation lookup, flagged as unverified in this offline pass). Key red flags on the raw fields alone, independent of the embedded description:
  - `authenticationRequirement` drops to **singleFactorAuthentication** despite the user's baseline pattern requiring MFA — suggests the sign-in satisfied an existing session/token rather than performing fresh interactive auth.
  - `isInteractive: false` — a non-interactive sign-in producing a fresh session from a new/hostile IP is consistent with token or cookie reuse rather than a live user typing credentials.
  - `sessionId: "sess_9f2a-copied"` — the literal string "-copied" in a session identifier is a strong (if perhaps lab-injected) indicator of session material duplication/replay.
  - Geolocation jumps from Edinburgh, GB to an anonymized VPN/exit-node identity in under 2 hours — impossible-travel-style anomaly, though the "impossible" element is weakened somewhat since the location field itself is non-attributable (VPN), not a second named city.
- **11:11:29Z** — A **newly created service principal** (`sp-datasync-prod`, created seven minutes earlier — see Audit Analysis) signs in directly via the **Microsoft Graph** client, from the same suspicious IP 185.220.101.47. Service principal auth has no interactive/MFA/CA gating in this record, meaning this identity bypasses the user-targeted MFA and Conditional Access controls that protect jsmith entirely — a classic technique to keep operating after the initial foothold in case the stolen session/cookie is revoked.
- **11:20:55Z** — jsmith signs in again, interactively, MFA satisfied, from an Edinburgh-consistent IP (different from the 09:14 IP but same city/geography, plausible as a second legitimate egress point e.g. mobile vs. office network). This looks like the genuine user continuing normal activity, unaware of the intervening compromise — it does **not** cancel out the 11:04 anomaly since the two sign-ins used materially different auth strength and origin.

## 2. Audit Log Analysis

| Time (UTC) | Activity | Initiated By | Source IP | Target | Detail |
|---|---|---|---|---|---|
| 11:07:41 | Add service principal | jsmith@meglab.onmicrosoft.com | 185.220.101.47 | sp-datasync-prod | New SP created |
| 11:09:03 | Add app role assignment to service principal | jsmith@meglab.onmicrosoft.com | 185.220.101.47 | sp-datasync-prod | Role: **Mail.Read** |

**Findings:**
- Both audit events are initiated by the jsmith identity, from the same suspicious IP as the anomalous sign-in, occurring 3–5 minutes after the 11:04:18Z replay event — tightly clustered, consistent with a scripted/automated attack sequence rather than manual human pacing.
- **Add service principal** — creation of a new app identity (`sp-datasync-prod`) named to blend in with legitimate data-sync/integration tooling. This is a textbook persistence move: an SP is not subject to the same interactive MFA/CA controls as a user account and typically authenticates via client secret/certificate, giving the attacker a durable credential independent of jsmith's password or session.
- **Add app role assignment — Mail.Read** — an application-level Graph API permission grant to the new SP. If this is an **application** (not delegated) permission, `Mail.Read` grants read access to mail in *every* mailbox in the tenant, not just jsmith's — a high-impact, low-noise exfiltration primitive. No subsequent mail-read activity appears in this dataset, so actual exfiltration is unconfirmed from this file alone (see open questions).
- No MFA-registration changes, conditional access policy edits, or additional role/global-admin grants appear in this dataset — the observed scope is narrowly: create SP → grant Mail.Read → use SP. This may reflect either a narrow/contained lab scenario or simply that this export doesn't cover the full audit trail.

## 3. Timeline (chronological)

1. **09:14:52Z** — jsmith signs in normally (Edinburgh, MFA, Browser) — baseline.
2. **11:04:18Z** — jsmith's identity produces a non-interactive, single-factor sign-in from a VPN/exit-node IP (185.220.101.47) using a session ID suggestive of copied/replayed session material.
3. **11:07:41Z** (+3m23s) — From the same IP, jsmith's identity creates a new service principal, `sp-datasync-prod`.
4. **11:09:03Z** (+1m22s) — From the same IP, jsmith's identity grants `sp-datasync-prod` the `Mail.Read` Graph API role.
5. **11:11:29Z** (+2m26s) — `sp-datasync-prod` authenticates directly via Microsoft Graph from the same IP, activating the new credential/permission chain and bypassing user-level MFA/CA entirely.
6. **11:20:55Z** (+9m26s) — jsmith signs in again interactively with MFA from a UK-consistent IP, appearing to be genuine, unrelated user activity.

**Plain-language summary:** A user's browser session appears to have been hijacked (likely via stolen session cookie/token) and used from anonymized infrastructure to authenticate without triggering MFA. Within minutes, the attacker used that access to stand up a new "service principal" application identity and grant it tenant-wide mail-read permissions — then immediately used that new identity to call the Graph API directly, establishing a persistence path that survives password resets or session revocation on the original user account. The legitimate user's own later sign-in suggests they were not obviously locked out and may be unaware.

## 4. MITRE ATT&CK Mapping (independent assessment)

| Behavior | Proposed Technique | Confidence | Note on embedded tag |
|---|---|---|---|
| Non-interactive, single-factor sign-in from new IP with reused/"copied" sessionId immediately after prior MFA'd session | **T1550.004** – Use Alternate Authentication Material: Web Session Cookie | High | Log embeds this exact ID. Independently concur — the `isInteractive:false` + auth-requirement downgrade + sessionId naming are consistent, structural evidence for this technique, not just the label being present. |
| Creation of new service principal shortly after suspicious sign-in | **T1136.003** – Create Account: Cloud Account | Medium-High | Log embeds this exact ID; concur — creating a new cloud identity (SP) for persistence fits. Could also be framed under T1098 family since it's an application/SP rather than a human account. |
| Granting `Mail.Read` app role to the new SP | **T1098.003** – Account Manipulation: Additional Cloud Roles (own proposal) | Medium | Log embeds **T1098.001** (Additional Cloud Credentials), which more precisely covers adding *authentication material* (secrets/certs) to an account/app. This event is a *permission/role grant*, not a credential addition — T1098.003 is a better structural fit on independent review. Both sub-techniques are plausible depending on what isn't shown in this excerpt (e.g., a client secret may also have been added but isn't in this log). |
| SP signs in via Graph API directly, bypassing user CA/MFA | **T1078.004** – Valid Accounts: Cloud Accounts | High | Log embeds this exact ID; concur — a functioning, credentialed cloud account (the SP) is used for access, and its use structurally bypasses controls scoped to human/interactive sign-ins. |
| (Anticipated, unconfirmed) potential mailbox data access via granted Mail.Read scope | **T1114** – Email Collection (candidate, not confirmed) | Low — speculative | Not tagged in source data; added as a likely *next* step the permission grant enables, but no record in this file shows Mail.Read actually being exercised to read mail. Needs corroboration. |

## 5. IOCs (for pivoting to other sources)

- **UPN:** `jsmith@meglab.onmicrosoft.com`
- **Tenant:** `meglab.onmicrosoft.com`
- **Malicious/suspect IP:** `185.220.101.47` (used for anomalous sign-in, both audit events, and SP sign-in — the single highest-value pivot IOC)
- **Legitimate-pattern IPs:** `20.190.128.14`, `51.140.22.9` (both associated with genuine Edinburgh, GB sign-ins — useful as a baseline to compare against)
- **Session ID:** `sess_9f2a-copied`
- **Service principal (attacker-created):** `sp-datasync-prod`
- **Granted permission/role:** `Mail.Read` (Graph API)
- **Client applications seen:** `Browser`, `Microsoft Graph`
- **Location strings:** `Edinburgh, GB` (legitimate baseline), `Unknown, Multiple VPN Exit Nodes` (attacker sign-in)
- **Key timestamps for cross-referencing:** `2026-07-18T11:04:18.000Z` (session hijack use), `2026-07-18T11:07:41.000Z` (SP creation), `2026-07-18T11:09:03.000Z` (role grant), `2026-07-18T11:11:29.000Z` (SP Graph activity)

## 6. Open Questions for Endpoint/EDR Correlation

1. What was jsmith's endpoint doing in the window immediately before **11:04:18Z** — is there evidence of browser cookie/session-storage access, credential-dumping tooling, or an infostealer process (the log's own description claims "~75 seconds after cookie exfil observed on endpoint" — this claim originates from the log file itself and needs independent EDR confirmation, not to be taken at face value)?
2. Is there any phishing email, malicious link click, or AiTM (adversary-in-the-middle) reverse-proxy artifact on jsmith's device in the hours prior that would explain how a session cookie was captured?
3. Was jsmith's endpoint device even active/online at 11:04:18Z? If the device was idle/locked at that moment, that strengthens the case the sign-in originated from attacker-controlled infrastructure using exfiltrated session material rather than the user's own machine.
4. Any outbound network connections, DNS resolutions, or process-level network activity from jsmith's device toward `185.220.101.47` or other Tor/VPN infrastructure?
5. Is there local evidence (browser extension installs, unusual scripts, PowerShell/curl/python invocations touching the browser's Cookies/LocalState SQLite files) consistent with automated session-token theft on jsmith's machine?
6. Do EDR logs show any process on jsmith's device around 11:07–11:11Z making Graph API calls or handling an app registration client secret/certificate for `sp-datasync-prod` — i.e., was the SP created from a compromised endpoint session, or purely cloud-side via the browser?
7. Were the two "legitimate-looking" jsmith sign-ins (09:14:52Z from `20.190.128.14` and 11:20:55Z from `51.140.22.9`) both initiated from the same physical device per EDR host telemetry, confirming they're genuinely the real user and not spoofed/replayed as well?
8. Does endpoint telemetry show any tooling capable of calling Microsoft Graph (e.g., a script or malware sample referencing `graph.microsoft.com`) that would corroborate the 11:11:29Z SP sign-in being driven from a device rather than purely attacker cloud infrastructure?
9. Is there any local mail-client or API activity on jsmith's device around/after 11:11:29Z suggesting Mail.Read was actively exercised (would help confirm or rule out T1114 Email Collection)?
