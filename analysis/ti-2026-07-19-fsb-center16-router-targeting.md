---
source_url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-194a
source_title: "Russian Government-Sponsored Activity Targets Poorly Configured and Vulnerable Devices Across Critical Sectors"
advisory_id: AA26-194A
extraction_date: 2026-07-19
publication_date: 2026-07-09
authoring_agencies: [NSA, CISA, FBI, DC3, ASD-ACSC, CSE-CCCS, NCSC-NZ, NCSC-UK, NUKIB, DDIS, EFIS, RIA, FDI, SUPO, ANSSI, AISE, AISI, SKW, NCSC-SE]
---

# TI Analysis: Russian FSB Center 16 — Router/Network Device Targeting (AA26-194A)

## Threat Overview

- **Threat actor:** Russian Federal Security Service (FSB) Center 16. Industry aliases: Berserk Bear, Energetic Bear, Crouching Yeti, Dragonfly, Ghost Blizzard, Static Tundra.
- **Target industries:** Communications, Defense Industrial Base, Energy, Financial Services, Government Services and Facilities (especially state/local level), Healthcare and Public Health.
- **Target regions:** Global/opportunistic — advisory co-sealed by agencies from the US, Australia, Canada, New Zealand, UK, Czech Republic, Denmark, Estonia, Finland, France, Italy, Poland, and Sweden, indicating multi-national victimology.
- **Time period:** "Decade-plus" of sustained activity. This CSA builds on an FBI PSA from August 2025 (I-082025-PSA, published 2025-08-20). Advisory itself published 2026-07-09.
- **Related/overlapping activity:** TTPs noted to overlap with those used by Salt Typhoon (Chinese state-sponsored actor) — mitigations in this advisory are stated to be effective against both.

## TTPs Mapped to MITRE ATT&CK (Enterprise v19)

Confidence is **High** for all techniques below — this is a joint advisory from 18 government agencies with detailed, specific technical description of actor tradecraft (not a generic/low-detail bulletin).

| Tactic | Technique | ID | Use in this campaign |
|---|---|---|---|
| Reconnaissance | Active Scanning: Scanning IP Blocks | [T1595.001](https://attack.mitre.org/versions/v19/techniques/T1595/001/) | Scans ranges of Internet IPs for devices with SNMP agents active |
| Reconnaissance | Active Scanning: Vulnerability Scanning | [T1595.002](https://attack.mitre.org/versions/v19/techniques/T1595/002/) | Scans victims for exploitable vulnerabilities/misconfigurations |
| Resource Development | Acquire Infrastructure: Virtual Private Servers | [T1583.003](https://attack.mitre.org/versions/v19/techniques/T1583/003/) | Leases VPS infrastructure to receive exfiltrated configs |
| Resource Development | Compromise Infrastructure: Network Devices | [T1584.008](https://attack.mitre.org/versions/v19/techniques/T1584/008/) | Compromises intermediate routers (e.g., as relay/proxy infra) |
| Resource Development | Obtain Capabilities: Exploits | [T1588.005](https://attack.mitre.org/versions/v19/techniques/T1588/005/) | Obtains/uses public exploit code for known CVEs |
| Initial Access | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/versions/v19/techniques/T1190/) | Exploits known CVEs in Cisco devices, Smart Install, and web management portals |
| Initial Access / C2 | Proxy | [T1090](https://attack.mitre.org/versions/v19/techniques/T1090/) | Directs scanning/exploit traffic through proxies; also reused for C2 (see below) |
| Execution | System Services | [T1569](https://attack.mitre.org/versions/v19/techniques/T1569/) | Executes commands via SNMP Set-Requests (e.g., config copy) |
| Privilege Escalation | Exploitation for Privilege Escalation | [T1068](https://attack.mitre.org/versions/v19/techniques/T1068/) | Exploits known CVEs for escalated device privileges |
| Defense Evasion | Obfuscated Files or Information | [T1027](https://attack.mitre.org/versions/v19/techniques/T1027/) | Spoofs source IP on SNMP Set-Requests so actions log as originating from local IPs |
| Credential Access | OS Credential Dumping | [T1003](https://attack.mitre.org/versions/v19/techniques/T1003/) | Collects router configs containing weak Cisco Type 7 / Type 0 passwords |
| Collection | Data from Configuration Repository: SNMP (MIB Dump) | [T1602.001](https://attack.mitre.org/versions/v19/techniques/T1602/001/) | Targets MIB objects to collect device/network info via SNMP |
| Collection | Data from Configuration Repository: Network Device Config Dump | [T1602.002](https://attack.mitre.org/versions/v19/techniques/T1602/002/) | Acquires credentials by dumping full device configuration |
| Command and Control | Proxy | [T1090](https://attack.mitre.org/versions/v19/techniques/T1090/) | Uses leased/compromised VPS as C2 proxy infrastructure |
| Command and Control | Application Layer Protocol | [T1071](https://attack.mitre.org/versions/v19/techniques/T1071/) | Runs TFTP/FTP services on actor infrastructure to receive exfil |
| Exfiltration | Exfiltration Over Alternative Protocol | [T1048](https://attack.mitre.org/versions/v19/techniques/T1048/) | Exfiltrates stolen config files via TFTP to VPS, separate from any C2 channel |

**CVEs exploited:**
- [CVE-2018-0171](https://www.cve.org/CVERecord?id=CVE-2018-0171) — Cisco Smart Install
- [CVE-2008-4128](https://www.cve.org/CVERecord?id=CVE-2008-4128) — affects only end-of-life Cisco devices

**MITRE D3FEND countermeasures referenced:** D3-ACH (Application Configuration Hardening), D3-MAN (Message Authentication), D3-MENCR (Message Encryption), D3-CH (Credential Hardening), D3-PM (Platform Monitoring), D3-NTF (Network Traffic Filtering), D3-NVA (Network Vulnerability Assessment).

## Indicators of Compromise

This advisory is **TTP-focused and does not publish a conventional IOC list** — no actor IP addresses, C2 domains, file hashes, or email addresses are provided. The only concrete artifacts given are:

- **File names (config exfil artifacts):** `config.bkp`, `output.txt`
- **SNMP OIDs used for exploitation (also useful as detection signatures):**
  - `1.3.6.1.4.1.9.9.96.1.1` — Cisco Config Copy
  - `1.3.6.1.4.1.9.9.96.1.1.1.1.5` — Config Copy Server Address (destination for exfil)
- **Ports/protocols of interest (for egress filtering/monitoring):**
  - UDP 69 (TFTP) — primary exfil channel
  - TCP 4786 (Cisco Smart Install)
  - UDP 161/162 (SNMPv1/v2)
  - TCP/UDP 10161/10162 (SNMPv3)
- **Password hash weakness:** Cisco password hashing Types 0, 4, and 7 flagged as insecure/plaintext-recoverable; Type 8 recommended.

## Simulation Plan (Atomic Red Team)

Checked live against the `redcanaryco/atomic-red-team` repo (master branch) on 2026-07-19. Coverage is sparse because most of this campaign's tradecraft targets **network appliances (SNMP/Cisco IOS)**, which is outside Atomic Red Team's primarily Windows/Linux/macOS host-based scope.

### Techniques WITH available atomic tests

| Technique | Tests available | Notes on applicability |
|---|---|---|
| [T1027](https://attack.mitre.org/versions/v19/techniques/T1027/) — Obfuscated Files or Information | 11 tests (e.g., base64-encoded PowerShell, obfuscated command line, compressed-file execution) | Tests are host/script obfuscation, not IP-spoofing — validates detection tooling for the tactic generically but doesn't replicate the specific TTP |
| [T1090.001](https://attack.mitre.org/versions/v19/techniques/T1090/001/) — Proxy: Internal Proxy | 3 tests (Connection Proxy on Linux/macOS/Windows, portproxy reg key) | Reasonable stand-in to validate proxy-traffic detection/logging |
| [T1071.001](https://attack.mitre.org/versions/v19/techniques/T1071/001/) — App Layer Protocol: Web Protocols | 3 tests (malicious user-agent beaconing) | Partial fit; actual campaign uses TFTP/FTP, not HTTP(S) |
| [T1071](https://attack.mitre.org/versions/v19/techniques/T1071/) (parent) | 1 test (Telnet C2) | Low fit |
| [T1048](https://attack.mitre.org/versions/v19/techniques/T1048/) — Exfiltration Over Alternative Protocol | 4 tests (SSH exfil x2, DNS exfil via `dig`/DoH) | No TFTP-specific test exists; DNS/SSH tests validate the tactic/detection pipeline, not the literal protocol |
| [T1003](https://attack.mitre.org/versions/v19/techniques/T1003/) — OS Credential Dumping | 7 tests (Gsecdump, NPPSpy, IIS AppCmd creds, Credential Manager dump, etc.) | Low fit — these are Windows host credential-dumping tests, not network device config exfiltration |

### Techniques with NO atomic tests (gap)

- **T1595.001 / T1595.002** (Active Scanning) — no ART coverage; simulate with `nmap`/custom SNMP scanner (e.g., `onesixtyone`, `snmpwalk`) against a lab device instead.
- **T1583.003** (Acquire VPS), **T1584.008** (Compromise Network Devices), **T1588.005** (Obtain Exploits) — Resource Development techniques generally aren't simulated by host-based atomics; not applicable to a technical purple-team exercise.
- **T1190** (Exploit Public-Facing Application) — no generic atomic exists (exploit is CVE-specific); use a CVE-2018-0171 PoC in an isolated lab against an unpatched Cisco IOS image if pursuing exploit validation.
- **T1090** (Proxy, parent) — no parent-level test, but see T1090.001 above as a partial substitute.
- **T1569** (System Services, parent) — no parent-level test.
- **T1068** (Exploitation for Privilege Escalation) — no generic atomic (inherently exploit/CVE-specific).
- **T1602.001 / T1602.002** (Data from Configuration Repository — SNMP/Network Device Config) — no ART coverage; this is the core, most distinctive TTP of the campaign and has no off-the-shelf atomic. Recommend a custom test: SNMP `Set-Request` against a lab router's Cisco Config Copy OID (`1.3.6.1.4.1.9.9.96.1.1.1.1.5`) to trigger a TFTP config push to a controlled listener — directly exercises the detection guidance CISA gives (IDS rule on inbound SNMP Set-Requests targeting that OID).

### Recommended prioritization

1. **Custom SNMP config-exfil simulation** (T1602.001/.002 + T1569 + T1048) — highest priority. This is the campaign's signature TTP and CISA gives you the exact OIDs to use; no atomic exists so this must be hand-built, but it directly tests the advisory's own detection recommendation (IDS rule on Set-Requests to the Config Copy OID).
2. **T1595.001/.002 scanning simulation** via `onesixtyone`/`nmap` SNMP community-string sweep — validates detection of the reconnaissance phase that precedes exploitation.
3. **T1027** (11 available atomics) and **T1090.001** (3 available atomics) — run as-is to validate general obfuscation/proxy detection, understanding they're host-based proxies for network-device-based tradecraft.
4. **T1190/CVE-2018-0171** — only pursue in an isolated lab with an actual vulnerable Cisco IOS image; do not attempt against production-adjacent infrastructure.

## Suggested Detections / Hunt Leads

- IDS/IPS rule for inbound SNMP Set-Requests containing OIDs `1.3.6.1.4.1.9.9.96.1.1*` (Cisco Config Copy family).
- Alert on outbound TFTP (UDP/69) sessions from network devices to non-management destinations.
- Alert on any SNMPv1/v2 traffic if SNMPv3 is meant to be enforced org-wide.
- Flag local-account logins on network devices where centralized/MFA-backed auth is the norm.
- Audit device configs for password hash Types 0, 4, 7 (weak/reversible) vs. Type 8 (recommended).
