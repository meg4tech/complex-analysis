---
source_url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-050a
source_title: "#StopRansomware: Ghost (Cring) Ransomware"
advisory_id: AA25-050A
extraction_date: 2026-07-29
publication_date: 2025-02-19
authoring_agencies: [FBI, CISA, MS-ISAC]
attack_version: 16.1
---

# TI Analysis: Ghost (Cring) Ransomware (AA25-050A)

## Threat Overview

- **Threat actor:** "Ghost" — a financially motivated ransomware crew located in China. Attribution has been fragmented over time because the group rotates payloads, file extensions, ransom note text, and contact addresses.
- **Known aliases:** Ghost, Cring, Crypt3r, Phantom, Strike, Hello, Wickrme, HsHarada, Rapture.
- **Target industries:** Critical infrastructure, schools and universities, healthcare, government networks, religious institutions, technology and manufacturing, and a large tail of SMBs.
- **Target regions:** Over 70 countries — **including organizations inside China**. Targeting is opportunistic/indiscriminate, driven by internet-facing vulnerability scanning rather than victim selection.
- **Time period:** Activity from early 2021 through at least January 2025 (date of the most recent FBI investigative findings). Advisory published 2025-02-19.
- **Motivation:** Financial. Ransom demands range from tens to hundreds of thousands of dollars in cryptocurrency.

**Operational signature worth internalizing:** Ghost is a *fast* actor — typically only a few days on a network, and in multiple cases initial compromise to ransomware deployment happened **within the same day**. Persistence is not a priority for them. Two behavioral notes with direct defensive value:

1. **When lateral movement fails, they abandon the victim.** Network segmentation is not just damage control here; it is an effective deterrent against this specific actor.
2. **Exfiltration is shallow.** Despite ransom notes threatening data sale, actual exfiltration is typically well under hundreds of GB and rarely includes meaningful IP or PII. Extortion leverage is largely bluff — relevant when advising on ransom decisions.

## TTPs Mapped to MITRE ATT&CK (Enterprise v16.1)

Confidence is **High** across the board unless noted — this is a joint FBI/CISA/MS-ISAC advisory sourced from direct FBI incident response, with specific command lines, tool names, and hashes rather than generic bulletin language.

| Tactic | Technique | ID | Use in this campaign | Conf. |
|---|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/versions/v16/techniques/T1190/) | Exploits unpatched internet-facing Fortinet, ColdFusion, SharePoint, Exchange using **publicly available exploit code** | High |
| Execution | Windows Management Instrumentation | [T1047](https://attack.mitre.org/versions/v16/techniques/T1047/) | WMIC used to run PowerShell on additional hosts to spread Beacon | High |
| Execution | Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/versions/v16/techniques/T1059/001/) | Downloads/executes Cobalt Strike; also used for defense evasion commands | High |
| Execution | Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/versions/v16/techniques/T1059/003/) | cmd.exe used to pull malicious content onto compromised servers | High |
| Persistence | Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/versions/v16/techniques/T1505/003/) | Web shells uploaded to compromised web servers (observed again in 2024) | High |
| Persistence | Account Manipulation | [T1098](https://attack.mitre.org/versions/v16/techniques/T1098/) | Changes passwords on existing accounts | Medium — described as "sporadic" |
| Persistence | Create Account: Local Account | [T1136.001](https://attack.mitre.org/versions/v16/techniques/T1136/001/) | Creates/modifies local accounts | Medium — "sporadic" |
| Persistence | Create Account: Domain Account | [T1136.002](https://attack.mitre.org/versions/v16/techniques/T1136/002/) | Creates/modifies domain accounts | Medium — "sporadic" |
| Priv Esc | Access Token Manipulation: Token Impersonation/Theft | [T1134.001](https://attack.mitre.org/versions/v16/techniques/T1134/001/) | Built-in Cobalt Strike token theft against SYSTEM-context processes, then re-runs Beacon elevated | High |
| Priv Esc | Exploitation for Privilege Escalation | [T1068](https://attack.mitre.org/versions/v16/techniques/T1068/) | SharpZeroLogon (CVE-2020-1472), SharpGPPPass (CVE-2014-1812), BadPotato, GodPotato | High |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | [T1562.001](https://attack.mitre.org/versions/v16/techniques/T1562/001/) | Disables AV; runs a specific `Set-MpPreference` command to gut Windows Defender (see below) | High |
| Defense Evasion | Hide Artifacts: Hidden Window | [T1564.003](https://attack.mitre.org/versions/v16/techniques/T1564/003/) | `powershell -nop -w hidden` in the lateral movement command | High |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | [T1070.001](https://attack.mitre.org/versions/v16/techniques/T1070/001/) | Ransomware payloads clear Windows Event Logs at execution | High |
| Credential Access | OS Credential Dumping | [T1003](https://attack.mitre.org/versions/v16/techniques/T1003/) | Cobalt Strike `hashdump` and Mimikatz | High |
| Discovery | Remote System Discovery | [T1018](https://attack.mitre.org/versions/v16/techniques/T1018/) | Ladon 911, SharpNBTScan (NBT.exe) | High |
| Discovery | Process Discovery | [T1057](https://attack.mitre.org/versions/v16/techniques/T1057/) | Cobalt Strike `ps` to enumerate running processes | High |
| Discovery | Account Discovery: Domain Account | [T1087.002](https://attack.mitre.org/versions/v16/techniques/T1087/002/) | `net group "Domain Admins" /domain` | High |
| Discovery | Network Share Discovery | [T1135](https://attack.mitre.org/versions/v16/techniques/T1135/) | SharpShares.exe for share enumeration / host discovery | High |
| Discovery | Software Discovery | [T1518](https://attack.mitre.org/versions/v16/techniques/T1518/) | Determines what security software is installed | High |
| Discovery | Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/versions/v16/techniques/T1518/001/) | Enumerates running AV via Cobalt Strike, precursor to disabling it | High |
| Lateral Movement | *(via T1047 + T1059.001)* | — | WMIC-invoked base64 PowerShell to detonate Beacon in memory on adjacent hosts | High |
| C2 | Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/versions/v16/techniques/T1071/001/) | Cobalt Strike Beacon/Team Server over HTTP/HTTPS | High |
| C2 | Ingress Tool Transfer | [T1105](https://attack.mitre.org/versions/v16/techniques/T1105/) | Beacon delivers ransomware payloads to victim servers | High |
| C2 | Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/versions/v16/techniques/T1132/001/) | Base64-encoded PowerShell (`-encodedcommand`) for lateral movement | High |
| C2 | Encrypted Channel | [T1573](https://attack.mitre.org/versions/v16/techniques/T1573/) | Encrypted email providers (Tutanota, Skiff, ProtonMail, Onionmail, Mailfence) for victim comms | High |
| Exfiltration | Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/versions/v16/techniques/T1041/) | Limited data pulled down to Cobalt Strike Team Servers | Medium — explicitly "limited" |
| Exfiltration | Exfiltration to Cloud Storage | [T1567.002](https://attack.mitre.org/versions/v16/techniques/T1567/002/) | Mega.nz, plus web shells for small-volume exfil | Medium — third-party reported, "limited uses" |
| Impact | Data Encrypted for Impact | [T1486](https://attack.mitre.org/versions/v16/techniques/T1486/) | Cring.exe / Ghost.exe / ElysiumO.exe / Locker.exe; directory-scoped or full-disk depending on CLI args | High |
| Impact | Inhibit System Recovery | [T1490](https://attack.mitre.org/versions/v16/techniques/T1490/) | Disables Volume Shadow Copy Service and deletes shadow copies | High |

### CVEs exploited for initial access

| CVE | Product | Note |
|---|---|---|
| [CVE-2018-13379](https://nvd.nist.gov/vuln/detail/CVE-2018-13379) | Fortinet FortiOS SSL VPN | Path traversal / credential disclosure |
| [CVE-2010-2861](https://nvd.nist.gov/vuln/detail/CVE-2010-2861) | Adobe ColdFusion | Directory traversal |
| [CVE-2009-3960](https://nvd.nist.gov/vuln/detail/CVE-2009-3960) | Adobe ColdFusion (BlazeDS) | XML external entity |
| [CVE-2019-0604](https://nvd.nist.gov/vuln/detail/CVE-2019-0604) | Microsoft SharePoint | Deserialization RCE |
| [CVE-2021-34473](https://nvd.nist.gov/vuln/detail/CVE-2021-34473) | Microsoft Exchange | **ProxyShell** chain |
| [CVE-2021-34523](https://nvd.nist.gov/vuln/detail/CVE-2021-34523) | Microsoft Exchange | **ProxyShell** chain |
| [CVE-2021-31207](https://nvd.nist.gov/vuln/detail/CVE-2021-31207) | Microsoft Exchange | **ProxyShell** chain |

Post-access CVEs used by their tooling: [CVE-2020-1472](https://nvd.nist.gov/vuln/detail/CVE-2020-1472) (ZeroLogon, via SharpZeroLogon), [CVE-2014-1812](https://nvd.nist.gov/vuln/detail/CVE-2014-1812) (GPP passwords, via SharpGPPPass), [CVE-2017-0143](https://nvd.nist.gov/vuln/detail/CVE-2017-0143)/[CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144) (MS17-010 scanning, via Ladon 911).

> **Note on the advisory's own key-takeaway list:** the summary box omits CVE-2019-0604 (SharePoint), which *is* named in the Initial Access body text. Patch scope should be driven by the body, not the takeaway box.

## Indicators of Compromise

### High-value behavioral IOC — the Defender disable command

This is the single most detectable artifact in the advisory. Ghost "frequently" runs:

```powershell
Set-MpPreference -DisableRealtimeMonitoring 1 -DisableIntrusionPreventionSystem 1 -DisableBehaviorMonitoring 1 -DisableScriptScanning 1 -DisableIOAVProtection 1 -EnableControlledFolderAccess Disabled -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
```

### High-value behavioral IOC — the lateral movement command prefix

Every observed lateral-movement invocation begins with this exact string:

```
powershell -nop -w hidden -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIA
```

Decodes to `$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("` — the standard Cobalt Strike in-memory loader stub. The constant prefix makes this a reliable string-match detection.

### File hashes (MD5)

| File name | MD5 |
|---|---|
| Cring.exe | `c5d712f82d5d37bb284acd4468ab3533` |
| Ghost.exe | `34b3009590ec2d361f07cac320671410` |
| Ghost.exe | `d9c019182d88290e5489cdf3b607f982` |
| ElysiumO.exe | `29e44e8994197bdb0c2be6fc5dfc15c2` |
| ElysiumO.exe | `c9e35b5c1dc8856da25965b385a26ec4` |
| ElysiumO.exe | `d1c5e7b8e937625891707f8b4b594314` |
| Locker.exe | `ef6a213f59f3fbee2894bd6734bbaed2` |
| iex.txt, pro.txt (IOX) | `ac58a214ce7deb3a578c10b97f93d9c3` |
| x86.log (IOX) | `c3b8f6d102393b4542e9f951c9435255` |
| x86.log (IOX) | `0a5c4ad3ec240fbfd00bdc1d36bd54eb` |
| sp.txt (IOX) | `ff52fdf84448277b1bc121f592f753c5` |
| main.txt (IOX) | `a2fd181f57548c215ac6891d000ec6b9` |
| isx.txt (IOX) | `625bd7275e1892eac50a22f8b4a6355d` |
| sock.txt (IOX) | `db38ef2e3d4d8cb785df48f458b35090` |

**Caveat:** MD5-only, and the advisory explicitly states Ghost rotates executables. Treat these as low-durability retrospective hunt indicators, not preventive blocklist material. Note the `.txt`/`.log` extensions on IOX payloads — masquerading as benign file types is itself the hunt lead.

### Tooling (hunt for presence, not hashes)

| Tool | Filename | Purpose | Source |
|---|---|---|---|
| Cobalt Strike | — | C2 / Beacon (cracked build) | commercial |
| IOX | iex.txt, pro.txt, x86.log, sp.txt, main.txt, isx.txt, sock.txt | Reverse proxy to C2 | `github[.]com/EddieIvan01/iox` |
| SharpShares | SharpShares.exe | Network share enumeration | `github[.]com/mitchmoser/SharpShares` |
| SharpZeroLogon | SharpZeroLogon.exe | CVE-2020-1472 against DCs | `github[.]com/leitosama/SharpZeroLogon` |
| SharpGPPPass | SharpGPPPass.exe | CVE-2014-1812 GPP password extraction | — |
| SpnDump | SpnDump.exe | SPN / service + hostname enumeration | — |
| SharpNBTScan | NBT.exe | NetBIOS scanning | `github[.]com/BronzeTicket/SharpNBTScan` |
| BadPotato | BadPotato.exe | Privilege escalation | `github[.]com/BeichenDream/BadPotato` |
| GodPotato | God.exe | Privilege escalation | `github[.]com/BeichenDream/GodPotato` |
| HFS | — | HTTP file server for staging/exfil | `rejitto[.]com/hfs` |
| Ladon 911 | — | Scanning/exploitation, MS17010 module | `github[.]com/k8gege/Ladon` |
| Web shell | — | Backdoor / persistence | variant of `github[.]com/BeichenDream/Chunk-Proxy/blob/main/proxy.aspx` |

CISA's framing is worth repeating verbatim to a SOC: *"These privilege escalation tools would not generally be used by individuals with legitimate access and credentials"* and *"Network administrators would be unlikely to use these tools for network share or remote systems discovery."* Presence alone is actionable.

### Network indicators

**No C2 IP addresses or domains are published in this advisory.** Ghost rarely registers domains — Beacon retrieval references the C2 server IP directly. The pattern given is:

```
http://<C2_IP>:80/Google.com
```

A URI path that mimics a domain name (`/Google.com`) on a direct-to-IP HTTP request is the hunt signature here.

### Ransom email addresses (33)

`asauribe@tutanota.com`, `cringghost@skiff.com`, `crptbackup@skiff.com`, `d3crypt@onionmail.org`, `d3svc@tuta.io`, `eternalnightmare@tutanota.com`, `evilcorp@skiff.com`, `fileunlock@onionmail.org`, `fortihooks@protonmail.com`, `genesis1337@tutanota.com`, `ghost1998@tutamail.com`, `ghostbackup@skiff.com`, `ghosts1337@skiff.com`, `ghosts1337@tuta.io`, `ghostsbackup@skiff.com`, `hsharada@skiff.com`, `just4money@tutanota.com`, `kellyreiff@tutanota.com`, `kev1npt@tuta.io`, `lockhelp1998@skiff.com`, `r.heisler@skiff.com`, `rainbowforever@skiff.com`, `rainbowforever@tutanota.com`, `retryit1998@mailfence.com`, `retryit1998@tutamail.com`, `rsacrpthelp@skiff.com`, `rsahelp@protonmail.com`, `sdghost@onionmail.org`, `shadowghost@skiff.com`, `shadowghosts@tutanota.com`, `summerkiller@mailfence.com`, `summerkiller@tutanota.com`, `webroothooks@tutanota.com`

Note `fortihooks@` and `webroothooks@` — the actor names the exploited vendor (Fortinet) and a security vendor (Webroot) in their own addresses.

### TOX IDs (used in ransom notes from ~August 2024)

```
EFE31926F41889DBF6588F27A2EC3A2D7DEF7D2E9E0A1DEFD39B976A49C11F0E19E03998DBDA
E83CD54EAAB0F31040D855E1ED993E2AC92652FF8E8742D3901580339D135C6EBCD71002885B
```

## Simulation Plan (Atomic Red Team)

Coverage checked live against `redcanaryco/atomic-red-team` **master branch on 2026-07-29** via the GitHub contents API and raw YAML retrieval. Test counts are from the current atomic YAML files, not from memory.

### Techniques WITH atomic coverage

| Technique | Tests | Fit assessment |
|---|---|---|
| [T1105](https://attack.mitre.org/versions/v16/techniques/T1105/) — Ingress Tool Transfer | 39 | Excellent. Broadest coverage available; exercises the payload-delivery step directly. |
| [T1087.002](https://attack.mitre.org/versions/v16/techniques/T1087/002/) — Domain Account Discovery | 24 | Excellent. Includes the exact `net group "Domain Admins" /domain` pattern. |
| [T1059.001](https://attack.mitre.org/versions/v16/techniques/T1059/001/) — PowerShell | 22 | Excellent, incl. encoded-command variants. |
| [T1018](https://attack.mitre.org/versions/v16/techniques/T1018/) — Remote System Discovery | 22 | Strong. No Ladon/SharpNBTScan test, but covers the tactic. |
| [T1098](https://attack.mitre.org/versions/v16/techniques/T1098/) — Account Manipulation | 17 | Strong. |
| [T1490](https://attack.mitre.org/versions/v16/techniques/T1490/) — Inhibit System Recovery | 13 | **Excellent — direct hit.** "Delete Volume Shadow Copies", "…via WMI", "…via WMI with PowerShell", "Modify VSS Service Permissions" all match Ghost behavior precisely. |
| [T1135](https://attack.mitre.org/versions/v16/techniques/T1135/) — Network Share Discovery | 12 | Strong substitute for SharpShares. |
| [T1518.001](https://attack.mitre.org/versions/v16/techniques/T1518/001/) — Security Software Discovery | 11 | **Excellent.** Includes "Windows Defender Enumeration", "AV Discovery via WMI", "Get Windows Defender exclusion settings using WMIC". |
| [T1136.001](https://attack.mitre.org/versions/v16/techniques/T1136/001/) — Create Local Account | 10 | Strong. |
| [T1047](https://attack.mitre.org/versions/v16/techniques/T1047/) — WMI | 10 | **Excellent — core lateral movement mechanism.** |
| [T1486](https://attack.mitre.org/versions/v16/techniques/T1486/) — Data Encrypted for Impact | 10 | Good. Includes an Akira ransomware-emulation test and ransom-note drops; no Ghost-specific test. Run in an isolated VM only. |
| [T1057](https://attack.mitre.org/versions/v16/techniques/T1057/) — Process Discovery | 9 | Strong. |
| [T1003](https://attack.mitre.org/versions/v16/techniques/T1003/) — OS Credential Dumping | 7 | Good; sub-techniques T1003.001–.008 all exist separately for deeper Mimikatz/LSASS coverage. |
| [T1059.003](https://attack.mitre.org/versions/v16/techniques/T1059/003/) — Windows Command Shell | 6 | Good. |
| [T1518](https://attack.mitre.org/versions/v16/techniques/T1518/) — Software Discovery | 6 | Good. |
| [T1136.002](https://attack.mitre.org/versions/v16/techniques/T1136/002/) — Create Domain Account | 5 | Good. |
| [T1134.001](https://attack.mitre.org/versions/v16/techniques/T1134/001/) — Token Impersonation/Theft | 5 | **Excellent — direct hit.** Contains a literal **"Bad Potato"** test and a "Juicy Potato" test, matching Ghost's BadPotato.exe/God.exe tooling. |
| [T1132.001](https://attack.mitre.org/versions/v16/techniques/T1132/001/) — Standard Encoding | 3 | Good — "Base64 Encoded data" maps to the encoded-command TTP. |
| [T1564.003](https://attack.mitre.org/versions/v16/techniques/T1564/003/) — Hidden Window | 3 | **Direct hit** on the `-w hidden` flag. |
| [T1071.001](https://attack.mitre.org/versions/v16/techniques/T1071/001/) — Web Protocols | 3 | Moderate — user-agent beaconing tests; not Beacon-specific. |
| [T1041](https://attack.mitre.org/versions/v16/techniques/T1041/) — Exfil Over C2 | 2 | Moderate. "C2 Data Exfiltration" is the relevant one. |
| [T1567.002](https://attack.mitre.org/versions/v16/techniques/T1567/002/) — Exfil to Cloud Storage | 2 | **Direct hit** — "Exfiltrate data with rclone to cloud Storage - **Mega** (Windows)" matches the reported Mega.nz usage exactly. |
| [T1505.003](https://attack.mitre.org/versions/v16/techniques/T1505/003/) — Web Shell | 1 | Thin — "Web Shell Written to Disk" only. Supplement with a custom `.aspx` drop mirroring the Chunk-Proxy variant. |
| [T1573](https://attack.mitre.org/versions/v16/techniques/T1573/) — Encrypted Channel | 1 | Low fit — "OpenSSL C2". Ghost's use of T1573 is encrypted *email* for victim comms, which is not simulable and not detection-relevant on the endpoint. Skip. |

### Techniques with NO atomic coverage (gaps)

Verified absent from `atomics/` on master as of 2026-07-29:

- **[T1562.001](https://attack.mitre.org/versions/v16/techniques/T1562/001/) — Impair Defenses: Disable or Modify Tools.** No `T1562` directory exists at all in the current repo. This is the **most significant gap**, because the `Set-MpPreference` command above is Ghost's most distinctive and most detectable artifact. **Build a custom atomic** that runs the exact documented command line in a lab VM and verify your EDR alerts on it. Do not skip this one.
- **[T1070.001](https://attack.mitre.org/versions/v16/techniques/T1070/001/) — Clear Windows Event Logs.** The `T1070` parent directory exists but contains only two FSUtil-based tests — no event-log clearing. **Build a custom atomic** using `wevtutil cl` / `Clear-EventLog` and confirm log-clearing alerts fire.
- **[T1190](https://attack.mitre.org/versions/v16/techniques/T1190/) — Exploit Public-Facing Application.** No atomic exists (exploitation is inherently CVE-specific). Validate via vulnerability scanning for the seven CVEs above rather than exploitation; if you want live exploit validation, use an isolated lab with a deliberately unpatched Exchange/FortiOS image.
- **[T1068](https://attack.mitre.org/versions/v16/techniques/T1068/) — Exploitation for Privilege Escalation.** No atomic. Partially covered in practice by the T1134.001 "Bad Potato"/"Juicy Potato" tests, which exercise the same tooling family Ghost uses.
- **Lateral movement as a chained behavior.** No single atomic reproduces WMIC → encoded PowerShell → in-memory Beacon. Chain T1047 + T1132.001 + T1564.003 + T1105 manually to approximate it.

### Recommended prioritization

Ordered by (high confidence) × (available coverage) × (distinctiveness to this actor):

1. **Custom atomic: the `Set-MpPreference` Defender-disable command (T1562.001).** Highest priority despite — actually *because of* — having no ART coverage. Exact command line is published, it is frequently used, and no legitimate admin workflow disables seven Defender protections in one invocation. If nothing else on this list gets done, do this.
2. **T1490 — Inhibit System Recovery (13 tests).** Direct behavioral match, runs immediately pre-encryption, and is the last reliable interdiction point before data loss. Highest-value detection in the whole chain.
3. **T1134.001 — Token Impersonation (5 tests, incl. "Bad Potato").** Direct tooling match to Ghost's BadPotato.exe/God.exe.
4. **T1047 + T1132.001 + T1564.003 chained.** Reproduces the signature lateral movement command. Also validate a plain string-match detection on the constant `powershell -nop -w hidden -encodedcommand JABzAD0A…` prefix.
5. **T1518.001 — Security Software Discovery (11 tests).** The reconnaissance step immediately preceding #1; catching it buys you time before defenses are disabled.
6. **T1087.002 (24) + T1135 (12) + T1018 (22) — discovery burst.** Ghost runs these in rapid succession; the *clustering* is the signal, so run them as a timed sequence rather than in isolation and check whether your correlation logic fires on the burst.
7. **Custom atomic: `wevtutil cl` event log clearing (T1070.001).**
8. **T1105 (39) + T1059.001 (22) + T1059.003 (6).** Broad, generically useful, lower actor-specificity.
9. **T1003 — Credential dumping (7, plus 8 sub-technique sets).**
10. **T1486 — Encryption (10).** Isolated VM only; primarily validates that you detect encryption *before* it matters, which by then is late.
11. **T1567.002 "rclone to Mega"** and **T1041 "C2 Data Exfiltration"** — lower priority given exfil is shallow and largely bluff, but cheap to run.

**Skip:** T1573 (encrypted email is out of endpoint scope), T1098/T1136.001/T1136.002 (medium confidence, "sporadic" behavior — run only if you have spare cycles).

## Suggested Detections / Hunt Leads

**Highest signal:**
- Alert on `Set-MpPreference` with **any** of `-DisableRealtimeMonitoring`, `-DisableBehaviorMonitoring`, `-DisableIOAVProtection`, `-DisableScriptScanning`, `-MAPSReporting Disabled`, `-SubmitSamplesConsent NeverSend`. Multiple flags in one command line should be a high-severity alert, not a low-priority informational.
- String-match on the constant encoded-command prefix `JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBt` (decodes to the Cobalt Strike memory-stream loader stub).
- Alert on `powershell` invoked with `-nop -w hidden -encodedcommand` in combination — individually noisy, jointly rare.
- WMIC spawning PowerShell on remote hosts (`wmic /node:` + `process call create`).

**Tool presence (any hit warrants investigation):**
- Filenames: `SharpShares.exe`, `SharpZeroLogon.exe`, `SharpGPPPass.exe`, `SpnDump.exe`, `NBT.exe`, `BadPotato.exe`, `God.exe`, `Cring.exe`, `Ghost.exe`, `ElysiumO.exe`, `Locker.exe`.
- IOX artifacts masquerading as text/log files: `iex.txt`, `pro.txt`, `sp.txt`, `main.txt`, `isx.txt`, `sock.txt`, `x86.log` — hunt on PE magic bytes in files with `.txt`/`.log` extensions generally.
- HFS (`hfs.exe`) running on a server that has no business hosting files.

**Network:**
- Outbound HTTP to a bare IP (no domain) where the URI path resembles a hostname, e.g. `/Google.com` — a strong, low-false-positive Beacon-staging signature.
- Outbound connections to Mega.nz from servers.
- Internal SMB scanning consistent with Ladon's MS17010 module.

**Recovery/impact stage (late, but catchable):**
- `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, VSS service stop or permission modification.
- `wevtutil cl` / `Clear-EventLog` — especially Security or System logs on a server.

**Posture checks driven by this advisory:**
- Confirm patch status for all seven initial-access CVEs; **CVE-2019-0604 (SharePoint) is missing from the advisory's own key-takeaways box** — verify it explicitly.
- Confirm ZeroLogon (CVE-2020-1472) patching on all domain controllers.
- Audit SYSVOL for GPP `cpassword` XML remnants (CVE-2014-1812).
- Verify network segmentation actually blocks lateral movement — per FBI observation, failed lateral movement causes this actor to **abandon the target entirely**. This is the highest-ROI mitigation against Ghost specifically.
- Confirm offline/segmented backups. The advisory notes victims with unaffected backups generally restored without contacting the actors at all.
- Disable unused RDP/FTP/SMB exposure (the advisory says "RDP 3398" — this is a typo for **3389**).

## Source Notes

- Extracted with `defuddle parse --md` on 2026-07-29 from the CISA web version.
- Advisory version history: initial version 2025-02-19; no subsequent revisions listed as of extraction.
- ATT&CK mappings in the advisory target framework **v16.1**; links above use the v16 versioned URLs to match. Re-map if correlating against a newer ATT&CK version.
- Two discrepancies between the advisory's key-takeaways box and its body text are flagged inline above (missing CVE-2019-0604; RDP port typo).
