# PB-09: Phishing Email Triage

| | |
|---|---|
| **Trigger** | A user reports a suspicious email, or the mail gateway flags one |
| **MITRE ATT&CK** | T1566.001, T1566.002, T1598, T1656, T1204 |
| **Full playbook and cases** | [Phishing-Analysis-Lab](https://github.com/Abdullah0415/Phishing-Analysis-Lab) |

## Summary

1. **Safety:** analyse only in an isolated VM. No clicks, no opening attachments, VirusTotal by hash only, private URLScan scans, defang every IOC.
2. **Header:** compare From / Return-Path / Reply-To; check SPF, DKIM and DMARC **and which domain passed**; read the Received chain bottom to top; whois the sending IP and domains (age).
3. **Body and links:** identify the lure (urgency, fear, generic greeting); list link domains; scan suspicious links privately; remember that redirectors and trackers carry the platform's reputation, not the attacker's.
4. **Attachments:** `file`, `sha256sum`, VirusTotal hash search, `olevba`, OOXML `.rels` **and** document text (field-code hyperlinks).
5. **Verdict:** Malicious / Suspicious / Legitimate, with evidence and MITRE mapping.
6. **Respond:** block sender, domains, specific URLs and hashes (never shared provider IPs); search and purge; check who clicked, replied or entered data; reset credentials or block cards if needed; reply to the reporter.

## Lessons from the lab

- SPF/DKIM "pass" and a 0/92 VirusTotal score both appeared on confirmed phishing.
- A legitimate email tells one consistent story across all header fields and authentication.
- A dead landing page is recorded as "not observable", not as "clean".

See the [full triage checklist](https://github.com/Abdullah0415/Phishing-Analysis-Lab/blob/main/playbook.md) and the [five case reports](https://github.com/Abdullah0415/Phishing-Analysis-Lab/tree/main/cases).
