# Wireshark Network Traffic Analysis

This folder contains packet captures (.pcap) from my home lab demonstrating network traffic analysis and attack detection skills.

## Captures

- **nmap_wireshark.pcap** — Full Nmap service scan traffic, including SYN scan pattern, RST responses, and SYN-ACK confirmation of open ports.
- **samba_exploit_capture.pcap** — Samba usermap_script exploit (CVE-2007-2447) showing the SMB negotiation, malicious payload injection, and resulting reverse shell connection.
- **mysql_capture.pcap** — MySQL unauthenticated root login and database enumeration traffic captured in plaintext.

## Key Skills Demonstrated

- Live packet capture and analysis
- Display filter usage (SYN/SYN-ACK/RST detection)
- TCP stream reconstruction to extract exploit payloads
- Identifying reverse shell traffic patterns
- Recognizing plaintext credential exposure

## Tools Used

Wireshark 4.6.0
