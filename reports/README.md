# Module 9: Reports & Artifacts — Ghost (Cring) Ransomware

End-to-end threat intelligence pipeline output, built from the real CISA/FBI/MS-ISAC joint
advisory [AA25-050A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-050a)
(#StopRansomware: Ghost (Cring) Ransomware), rather than course sample data.

## Pipeline

1. **Ingestion** — `ti-2026-07-29-ghost-cring-ransomware.md` was produced by the `/ingest-ti`
   slash command built in Module 8 ([complex-analysis](https://github.com/meg4tech/complex-analysis)),
   run directly against the live CISA advisory URL via `defuddle`.
2. **Analysis** — the advisory's TTPs were mapped to 29 MITRE ATT&CK techniques (v16.1), and
   Atomic Red Team coverage was checked live against `redcanaryco/atomic-red-team` (master) to
   identify which techniques could be safely simulated and which had zero test coverage.
3. **Reporting** — the ingested findings were turned into three deliverables covering different
   audiences, generated in Claude Desktop's Chat tab.

## Contents

| File | Description |
|---|---|
| `ti-2026-07-29-ghost-cring-ransomware.md` | Raw ingestion output: TTPs, IOCs, ATT&CK mapping, Atomic Red Team gap analysis |
| `Ghost_Cring_TI_Report.docx` | Full threat intelligence report — TTPs, IOCs, simulation plan, detection recommendations, posture checks |
| `Ghost_Ransomware_Executive_Briefing.pptx` | 8-slide executive briefing adapted from the course's incident-briefing template |
| `detection-coverage-dashboard.html` | Interactive dashboard — Atomic Red Team simulation coverage across all 29 techniques, filterable by strong/partial/gap |
| `attack-timeline.html` | Interactive attack-progression timeline — Ghost's typical intrusion chain, colour-coded by ATT&CK tactic, with zoom and click-for-detail |

## Key findings

- **29 ATT&CK techniques mapped**, 11 with strong Atomic Red Team coverage (10+ tests), 13
  partial, **5 with zero coverage**.
- **Highest-priority gap:** T1562.001 (Impair Defenses) — Ghost's `Set-MpPreference` command
  that disables seven Windows Defender protections in a single line has no existing Atomic Red
  Team test and is the single most detectable artifact in the advisory.
- **Source discrepancy caught:** the advisory's own key-takeaways box omits CVE-2019-0604
  (SharePoint), which is named in the body text as an initial-access vector — patch scope should
  follow the body, not the summary.
- Confirmed a typo in the advisory's own mitigations section ("RDP 3398" → should read 3389).

## Note on adaptation

The course's Module 9 spec is written for an incident that happened to your organisation
(confirmed compromise, "current status: contained"). Since Ghost is a public advisory rather
than a live incident, the DOCX and PPTX were reframed as **proactive threat intelligence /
readiness review** products rather than incident response documents, while keeping the
course's required structure (slide count, section order, report sections) intact.
