# Project 8 — Network Traffic Analysis with Wireshark

- **Author:** Vijay S
- **Role Target:** SOC Analyst / Entry-Level Penetration Tester
- **Environment:** Wireshark · Nmap · Metasploit Framework · DVWA · Kali Linux · Isolated VMnet1 host-only network
- **Project Repo:** [github.com/JacobVijay26/Vijay_cybersecurity](https://github.com/JacobVijay26/Vijay_cybersecurity)

Packet-level capture and analysis of reconnaissance, exploitation, and web application attack traffic — reconstructing each attack directly from the wire rather than relying solely on tool output.

📄 **Full report:** [Project8_Wireshark_Report.docx](./Project8_Wireshark_Report.docx) · [PDF version](./Project8_Wireshark_Report.pdf)

---

## Objective

Capture live traffic across three distinct attack scenarios and demonstrate that a passive network observer — using nothing but Wireshark filters and TCP/HTTP stream reconstruction — can independently confirm scanning activity, exploitation, and full attack impact without access to the target host or the attacking tool's own logs.

## Lab Topology

| Host | Role | IP |
|---|---|---|
| Kali Linux | Attacker machine + packet capture host (eth0) | 192.168.100.129 |
| Metasploitable2 | Reconnaissance & exploitation target | 192.168.100.128 |
| DVWA-Ubuntu | Web application target | 192.168.100.30 |

All hosts sit on a VMnet1 host-only network (192.168.100.0/24), consistent with every other project in this portfolio.

---

## Scenarios Captured

| # | Capture File | Scenario | Key Evidence | MITRE ATT&CK |
|---|---|---|---|---|
| 1 | `02_nmap_recon.pcapng` | Nmap service/OS detection scan | SYN scan fingerprint, 23 open ports confirmed via SYN-ACK, vsFTPd 2.3.4 banner disclosure | T1595 — Active Scanning |
| 2 | `03_samba_exploit.pcapng` | Samba `usermap_script` remote exploit | Full malicious command reconstructed from raw SMB packet bytes | T1210 — Exploitation of Remote Services |
| 3 | `04_dvwa_web_attacks.pcapng` | DVWA SQL Injection | Full credential table leaked in cleartext HTTP, cross-validated with Project 7 | T1190 — Exploit Public-Facing Application |
| 4 | `04_dvwa_web_attacks.pcapng` | DVWA Reflected XSS | Unsanitized payload reflection with browser XSS protection explicitly disabled | T1189 — Drive-by Compromise |

---

## Highlights

- **No tool output was taken at face value** — every finding in the report is backed by a direct packet or stream screenshot, not just a claim that "the attack worked."
- **Full credential leak cross-validated three ways**: the same five DVWA user credentials recovered via in-band SQLi and Blind SQLi in Project 7 were confirmed a third time here, purely from passive network capture — proving the exposure is visible to any network observer, not just an active attacker.
- **Complete exploit payload reconstruction**: the Samba `usermap_script` exploit's actual shell command was extracted character-for-character from the SMB Account field in the packet capture, without relying on Metasploit's own success message.
- **A consistent theme across all three scenarios**: nothing observed was encrypted — every payload, credential, and command was fully readable in plaintext, reinforcing the case for TLS everywhere and network-level monitoring as an independent detection layer.

## Tools Used

Wireshark, Nmap, Metasploit Framework, DVWA, Kali Linux

## Repository Contents

- `Project8_Wireshark_Report.docx` / `.pdf` — full analysis report (methodology, evidence, impact, MITRE ATT&CK mapping, remediation)
- `screenshots/` — key evidence captures referenced in the report

## Related Projects

Part of a broader cybersecurity portfolio spanning blue team detection engineering and red team offensive security. See the [profile README](https://github.com/JacobVijay26/Vijay_cybersecurity) for the full project index.
