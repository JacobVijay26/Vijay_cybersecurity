# Project 2 — Incident Response Playbook: Ransomware

A structured, NIST SP 800-61-aligned Incident Response playbook for ransomware attacks, written as a practical reference document a SOC analyst or IR team could actually follow during a live incident — not just a theoretical write-up.

## Objective

Produce a complete, actionable ransomware IR playbook covering the full incident lifecycle: preparation, detection, containment, eradication, recovery, and lessons learned — paired with concrete detection signatures, communication templates, and evidence-collection guidance that ties directly back to tools used elsewhere in this portfolio (SIEM alert rules, Wireshark signatures).

## Framework

Built on **NIST SP 800-61 Rev 2**, the industry-standard incident response framework, adapted specifically for ransomware scenarios.

## What's Inside

| Section | Contents |
|---|---|
| Roles & Responsibilities | Escalation chain from L1 SOC Analyst through Incident Commander, IT, Legal, and Management |
| Attack Overview | Common ransomware vectors (phishing, RDP brute force, unpatched CVEs) and a full 7-phase attacker kill chain, each phase mapped to a detection opportunity |
| Detection & Identification | Network and host-based Indicators of Compromise (IOCs), plus a table of SIEM alert rules with trigger conditions and severity ratings |
| Incident Response Phases | Six phases (Preparation → Lessons Learned), each broken into concrete tasks with owners and response-time targets by severity |
| Communication Templates | Ready-to-use internal alert, management escalation, and regulatory notification templates |
| Evidence Collection Checklist | Step-by-step evidence preservation guidance |
| Wireshark Detection Signatures | Concrete packet-level signatures for port scans, exploit traffic, and data exfiltration |
| Recovery Checklist | Structured steps for safe restoration after containment and eradication |

## Highlights

- **Severity-based response time SLAs** — Critical incidents (active encryption, data exfiltration) require immediate escalation to the IR team and management; Low-severity events (a suspicious email with no action taken) are handled by L1 within an hour. This tiered structure keeps response effort proportional to actual risk.
- **IOCs span both network and host layers** — from Tor exit-node connections and SMB lateral movement traffic, to ransom-note filenames and `vssadmin delete shadows` shadow-copy deletion — giving detection coverage across the full attack surface, not just one layer.
- **Directly reusable SIEM alert logic** — rules like "Mass File Rename" (>100 extensions changed in 60 seconds) and "Credential Dumping" (lsass.exe memory access) are written as concrete, implementable trigger conditions, not abstract advice.
- **Grounded in the same kill-chain thinking used throughout this portfolio** — the 7-phase ransomware kill chain (Initial Access → Extortion) mirrors the MITRE ATT&CK-style structure used in every technical project here, keeping the whole portfolio conceptually consistent.

## Repository Contents

- `IR_Playbook_Ransomware_VIJAY_S.docx` / `.pdf` — the complete playbook

## Related Projects

Part of a broader cybersecurity portfolio spanning blue team detection engineering and red team offensive security. See the [profile README](https://github.com/JacobVijay26/Vijay_cybersecurity) for the full project index.
