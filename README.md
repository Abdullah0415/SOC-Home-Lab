<div align="center">

# 🛡️ SOC Home Lab
### Detection Engineering with Wazuh · Mapped to MITRE ATT&CK

*Simulating real attacker techniques, investigating the logs, closing the detection gaps with custom rules, and documenting the evidence — one exercise at a time.*

<br>

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh%204.x-0E7490?style=for-the-badge&logo=wazuh&logoColor=white)
![Sysmon](https://img.shields.io/badge/Telemetry-Sysmon-5C6BC0?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-C62828?style=for-the-badge)
![Kali Linux](https://img.shields.io/badge/Attacker-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![VMware](https://img.shields.io/badge/Lab-VMware-607078?style=for-the-badge&logo=vmware&logoColor=white)

<br>

**[📊 Detection Summary](#-detection-summary)** &nbsp;·&nbsp; **[🧪 Exercises](#-contents)** &nbsp;·&nbsp; **[📚 Docs](#-documentation)** &nbsp;·&nbsp; **[🎓 What I Learned](#-what-i-learned)** &nbsp;·&nbsp; **[🚀 Next Steps](#-next-steps)**

</div>

---

## Overview

A hands-on Security Operations Center (SOC) home lab built on VMware Workstation with a Wazuh SIEM, a Windows 11 endpoint running Sysmon, and a Kali Linux attacker. In each exercise I simulate a real attacker technique, investigate the resulting logs, close detection gaps with custom Wazuh rules mapped to MITRE ATT&CK, tune false positives, and document the evidence.

> **At a glance**
> - **13 exercises**, from brute-force detection to defense evasion and crash root-cause analysis
> - **12 custom detection rules** (levels 10 to 14) and **2 false-positive suppression rules**
> - **MITRE ATT&CK coverage:** T1136.001, T1033, T1547.001, T1053.005, T1021, T1021.001, T1105, T1110.001, T1078, T1565.001, T1070.001
> - **Skills:** Windows Event Log and Sysmon analysis, Linux auth log analysis, detection engineering, false-positive tuning, file integrity monitoring, defense-evasion detection, attack timelines, log-pipeline troubleshooting, crash dump analysis (WinDbg)

## 📚 Documentation

| Document | What it covers |
|---|---|
| 🖥️ [Lab architecture](docs/01-architecture.md) | VMs, network, telemetry pipeline and collection configuration |
| 📊 [Detection rules](docs/02-detection-rules.md) | Every custom rule with its parent, data source and MITRE mapping, plus documented gaps |
| 🎓 [Lessons learned](docs/03-lessons-learned.md) | What broke, what misled me, and what I do differently now |
| 🧾 [Playbooks](playbooks/) | Investigation checklists for the alerts this lab produces |
| ⚙️ [Rules](rules/) | The deployable `local_rules.xml` running on the Wazuh manager |
| 📈 [TryHackMe progress](docs/tryhackme-progress.md) | Rooms completed and how they connect to the lab |

<details>
<summary><b>Repository structure</b></summary>
<br>

```
SOC-Home-Lab/
├── README.md                 Overview, detection summary and all exercises
├── docs/
│   ├── 01-architecture.md
│   ├── 02-detection-rules.md
│   ├── 03-lessons-learned.md
│   └── tryhackme-progress.md
├── rules/
│   └── local_rules.xml       Custom Wazuh rules (deployable)
├── playbooks/                PB-01 … PB-05 investigation checklists
└── screenshots/
    └── Exercise-01 … Exercise-13
```

</details>

## 📑 Contents

- [Documentation](#-documentation)
- [Lab architecture](#-lab-architecture)
- [Detection summary](#-detection-summary)
- [Exercise 1: Windows Logon Brute Force](#exercise-1-windows-logon-brute-force)
- [Exercise 2: New Admin Account and Privilege Escalation](#exercise-2-new-admin-account-and-privilege-escalation)
- [Exercise 3: SSH Brute Force from Kali](#exercise-3-ssh-brute-force-from-kali)
- [Exercise 4: First Custom Detection Rule](#exercise-4-first-custom-detection-rule)
- [Exercise 5: Sysmon Telemetry and Recon Detection](#exercise-5-sysmon-telemetry-and-recon-detection)
- [Exercise 6: Persistence Detection](#exercise-6-persistence-detection)
- [Exercise 7: Attack Timeline and Alert Triage](#exercise-7-attack-timeline-and-alert-triage)
- [Exercise 8: Lateral Movement, Tool Transfer and Alert Tuning](#exercise-8-lateral-movement-tool-transfer-and-alert-tuning)
- [Exercise 9: Linux SSH Brute Force and Successful Login](#exercise-9-linux-ssh-brute-force-and-successful-login)
- [Exercise 10: File Integrity Monitoring and Startup Persistence](#exercise-10-file-integrity-monitoring-and-startup-persistence)
- [Exercise 11: Defense Evasion and Endpoint Health](#exercise-11-defense-evasion-and-endpoint-health)
- [Exercise 12: Endpoint Stability Troubleshooting](#exercise-12-endpoint-stability-troubleshooting-0x124-whea-crash)
- [Exercise 13: RDP Brute Force and Successful Remote Logon](#exercise-13-rdp-brute-force-and-successful-remote-logon)
- [What I learned](#-what-i-learned)
- [Next steps](#-next-steps)

## 🖥️ Lab architecture

| Role | Machine | IP / detail |
|---|---|---|
| Attacker | Kali Linux | 10.10.10.130 |
| Victim | Windows 11 Enterprise (agent: win11-victim) + Sysmon | 10.10.10.0/24 (DHCP) |
| SIEM | Wazuh on Ubuntu Server | 10.10.10.10 |

```mermaid
flowchart LR
    KALI["🐉 SOC-Kali<br/>Attacker<br/>10.10.10.130"]
    WIN["🪟 SOC-Win11<br/>Endpoint + Sysmon<br/>Wazuh agent"]
    WAZ["🛡️ SOC-Wazuh<br/>SIEM<br/>10.10.10.10"]
    KALI -- "SMB · RDP" --> WIN
    KALI -- "SSH" --> WAZ
    WIN -- "Logs · FIM<br/>TCP 1514" --> WAZ
```

Isolated NAT network 10.10.10.0/24. Dashboard: `https://10.10.10.10`. Full details: [docs/01-architecture.md](docs/01-architecture.md)

**Tools:** VMware Workstation Pro, Wazuh 4.x (SIEM/XDR), Sysmon (SwiftOnSecurity config), Kali Linux (nmap, hydra, netexec), PowerShell, Git

## 📊 Detection summary

| Rule | Exercise | Detects | MITRE ATT&CK | Level |
|---|---|---|---|---|
| 100100 | 4 | New Windows user created | T1136.001 Local Account | 12 |
| 100200 | 5 | `whoami` executed | T1033 System Owner/User Discovery | 10 |
| 100300 | 6 | Registry Run key modified | T1547.001 Run Keys / Startup Folder | 12 |
| 100400 | 6 | Scheduled task created | T1053.005 Scheduled Task | 12 |
| 100500 | 8 | Network logon (type 3) | T1021 Remote Services | 12 |
| 100600 | 8 | PowerShell web download | T1105 Ingress Tool Transfer | 12 |
| 100700 | 8 | Suppress: PowerShell policy-test file (benign) | n/a | 0 |
| 100710 | 8 | Suppress: `sdbinst -m -bg` run by PcaSvc (benign) | n/a | 0 |
| 100800 | 9 | SSH brute force that succeeded | T1110.001, T1078 | 14 |
| 100900 | 10 | Sensitive Finance file modified or deleted | T1565.001 Stored Data Manipulation | 10 |
| 100910 | 10 | File added to a Windows Startup folder | T1547.001 Run Keys / Startup Folder | 12 |
| 100930 | 11 | Windows event log cleared | T1070.001 Clear Windows Event Logs | 12 |
| 101000 | 13 | RDP remote interactive logon (type 10) | T1021.001 Remote Desktop Protocol | 6 |
| 101010 | 13 | RDP brute force that succeeded | T1110.001, T1021.001, T1078 | 14 |

Full rule details, MITRE coverage and documented visibility gaps: [docs/02-detection-rules.md](docs/02-detection-rules.md). Deployable rule file: [rules/local_rules.xml](rules/local_rules.xml). Investigation steps for these alerts: [playbooks/](playbooks/).

Screenshots for every exercise are in [`screenshots/`](screenshots/), one folder per exercise. Click any image to open it full size.

---

## Exercise 1: Windows Logon Brute Force

**Scenario:** Generated repeated failed logons on the Windows endpoint (Event ID 4625).

**Detection:** Wazuh recorded 5 failures with rule 60122 "Logon Failure - Unknown user or bad password", level 5.

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-01/EX1-Failed-Logins-4625.png"><img src="screenshots/Exercise-01/EX1-Failed-Logins-4625.png" width="400" alt="Failed logons in Wazuh"></a><br><sub>Failed logons in Wazuh</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-01/EX1-Failed-Events-4625%20close-up.png"><img src="screenshots/Exercise-01/EX1-Failed-Events-4625%20close-up.png" width="400" alt="Failed logon event detail"></a><br><sub>Failed logon event detail</sub></td>
  </tr>
</table>

---

## Exercise 2: New Admin Account and Privilege Escalation

**Scenario:** Created a hidden "backdoor" user and added it to the Administrators group.

**Detection:**
- Event 4720, user account created (MITRE: Account Manipulation)
- Event 4732, Administrators group changed, rule 60154, level 12

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-02/EX2-Hidden-Admin-4720.png"><img src="screenshots/Exercise-02/EX2-Hidden-Admin-4720.png" width="400" alt="New admin user created (4720)"></a><br><sub>New admin user created (4720)</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-02/EX2-Admin-Group-4732.png"><img src="screenshots/Exercise-02/EX2-Admin-Group-4732.png" width="400" alt="Administrators group changed (4732)"></a><br><sub>Administrators group changed (4732)</sub></td>
  </tr>
</table>

---

## Exercise 3: SSH Brute Force from Kali

**Scenario:** Scanned the network with nmap and ran hydra against the Wazuh server's SSH service.

**Detection:** rule 5503 "PAM: User login failed", level 5, MITRE ATT&CK T1110.001 Password Guessing.

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-03/EX3-Wazuh%20Dashboard.png"><img src="screenshots/Exercise-03/EX3-Wazuh%20Dashboard.png" width="400" alt="SSH brute force on the dashboard"></a><br><sub>SSH brute force on the dashboard</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-03/EX3-event%20detail-1.png"><img src="screenshots/Exercise-03/EX3-event%20detail-1.png" width="400" alt="Event detail: source IP"></a><br><sub>Event detail: source IP</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-03/EX3-event%20detail-2.png"><img src="screenshots/Exercise-03/EX3-event%20detail-2.png" width="400" alt="Event detail: rule and MITRE"></a><br><sub>Event detail: rule and MITRE</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-03/EX3-hydra%20attack.png"><img src="screenshots/Exercise-03/EX3-hydra%20attack.png" width="400" alt="hydra attack from Kali"></a><br><sub>hydra attack from Kali</sub></td>
  </tr>
</table>
<details>
<summary><b>More screenshots</b> (1)</summary>
<br>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-03/EX3-nmap%20scan.png"><img src="screenshots/Exercise-03/EX3-nmap%20scan.png" width="400" alt="nmap scan from Kali"></a><br><sub>nmap scan from Kali</sub></td>
  </tr>
</table>

</details>

---

## Exercise 4: First Custom Detection Rule

**Goal:** Flag new Windows user creation as a possible backdoor, at high severity.

**Custom rule 100100:** level 12, triggers on Event ID 4720, MITRE ATT&CK T1136.001 (Create Account: Local Account).

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-04/EX4-Custom-rule-dashboard.png"><img src="screenshots/Exercise-04/EX4-Custom-rule-dashboard.png" width="400" alt="Rule 100100 on the dashboard"></a><br><sub>Rule 100100 on the dashboard</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-04/EX4-Custom-rule-event-2.png"><img src="screenshots/Exercise-04/EX4-Custom-rule-event-2.png" width="400" alt="Rule 100100 event detail"></a><br><sub>Rule 100100 event detail</sub></td>
  </tr>
</table>
<details>
<summary><b>More screenshots</b> (2)</summary>
<br>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-04/EX4-Custom-rule-event.png"><img src="screenshots/Exercise-04/EX4-Custom-rule-event.png" width="400" alt="Rule 100100 event"></a><br><sub>Rule 100100 event</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-04/EX4-Custom-rule-event-1.png"><img src="screenshots/Exercise-04/EX4-Custom-rule-event-1.png" width="400" alt="Rule 100100 event (continued)"></a><br><sub>Rule 100100 event (continued)</sub></td>
  </tr>
</table>

</details>

---

## Exercise 5: Sysmon Telemetry and Recon Detection

**Scenario:** Applied the SwiftOnSecurity Sysmon configuration on the Windows endpoint, forwarded the Sysmon log to Wazuh, and simulated attacker reconnaissance (`whoami`, `whoami /priv`, `ipconfig /all`, `net user`).

**Findings:**
- Sysmon Event ID 1 (process creation) collected by Wazuh
- `net user` was caught by built-in rule 92031 (Discovery activity, level 3)
- `whoami` was logged by Sysmon but produced **no Wazuh alert**: a detection gap

**Custom rule 100200:** level 10 on `whoami.exe` execution, MITRE ATT&CK T1033.

```xml
<group name="local,sysmon,windows,">
<rule id="100200" level="10">
<if_group>sysmon_event1</if_group>
<field name="win.eventdata.image">whoami.exe</field>
<description>Custom SOC rule: whoami executed - possible host reconnaissance</description>
<mitre>
<id>T1033</id>
</mitre>
</rule>
</group>
```

**Troubleshooting:** after adding the rule, wazuh-manager failed to start (systemd timeout). I validated the rules with `wazuh-analysisd -t` (no errors), found stuck processes in the service status, cleared them with `wazuh-control stop`, and the manager started successfully.

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-05/EX5-recon-commands.png"><img src="screenshots/Exercise-05/EX5-recon-commands.png" width="400" alt="Recon commands on the victim"></a><br><sub>Recon commands on the victim</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-05/EX5-rule-100200-dashboard.png"><img src="screenshots/Exercise-05/EX5-rule-100200-dashboard.png" width="400" alt="Custom rule 100200 firing"></a><br><sub>Custom rule 100200 firing</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-05/EX5-rule-100200-event.png"><img src="screenshots/Exercise-05/EX5-rule-100200-event.png" width="400" alt="whoami event detail"></a><br><sub>whoami event detail</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-05/EX5-net-user-event.png"><img src="screenshots/Exercise-05/EX5-net-user-event.png" width="400" alt="net user caught by built-in rule 92031"></a><br><sub>net user caught by built-in rule 92031</sub></td>
  </tr>
</table>
<details>
<summary><b>More screenshots</b> (5)</summary>
<br>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-05/EX5-sysmon-eventviewer.png"><img src="screenshots/Exercise-05/EX5-sysmon-eventviewer.png" width="400" alt="Sysmon log in Event Viewer"></a><br><sub>Sysmon log in Event Viewer</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-05/EX5-sysmon-events.png"><img src="screenshots/Exercise-05/EX5-sysmon-events.png" width="400" alt="Sysmon events in Wazuh"></a><br><sub>Sysmon events in Wazuh</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-05/EX5-sysmon-events-list.png"><img src="screenshots/Exercise-05/EX5-sysmon-events-list.png" width="400" alt="Sysmon events list"></a><br><sub>Sysmon events list</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-05/EX5-sysmon-event1-detail.png"><img src="screenshots/Exercise-05/EX5-sysmon-event1-detail.png" width="400" alt="Sysmon Event 1 detail"></a><br><sub>Sysmon Event 1 detail</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-05/EX5-rule-100200-details.png"><img src="screenshots/Exercise-05/EX5-rule-100200-details.png" width="400" alt="Rule 100200 details"></a><br><sub>Rule 100200 details</sub></td>
  </tr>
</table>

</details>

---

## Exercise 6: Persistence Detection

**Scenario:** Simulated two common persistence techniques on the Windows endpoint and wrote a custom rule for each, using Sysmon telemetry.

| Technique | Telemetry | Built-in result | Custom rule |
|---|---|---|---|
| Registry Run key (fake "Updater" value under `HKCU\...\CurrentVersion\Run`) | Sysmon Event 13 | Rule 92302, level 6 | **100300**, level 12, T1547.001 |
| Scheduled task (fake "WindowsUpdateCheck" via `schtasks`) | Sysmon Event 1 | **No alert** (gap) | **100400**, level 12, T1053.005 |

**Notes:**
- The registry path is backslash-escaped in Wazuh's JSON, so the regex needed `CurrentVersion\\+Run` to match.
- Rule 100400 needs two conditions (`schtasks.exe` AND `/create`) to avoid false positives.

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-06/EX6-rule-100300-dashboard.png"><img src="screenshots/Exercise-06/EX6-rule-100300-dashboard.png" width="400" alt="Run key rule 100300 firing"></a><br><sub>Run key rule 100300 firing</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-06/EX6-rule-100400-dashboard.png"><img src="screenshots/Exercise-06/EX6-rule-100400-dashboard.png" width="400" alt="Scheduled task rule 100400 firing"></a><br><sub>Scheduled task rule 100400 firing</sub></td>
  </tr>
</table>
<details>
<summary><b>More screenshots</b> (8)</summary>
<br>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-06/EX6-runkey-attack.png"><img src="screenshots/Exercise-06/EX6-runkey-attack.png" width="400" alt="Run key created on the victim"></a><br><sub>Run key created on the victim</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-06/EX6-runkey-builtin.png"><img src="screenshots/Exercise-06/EX6-runkey-builtin.png" width="400" alt="Built-in rule for the Run key"></a><br><sub>Built-in rule for the Run key</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-06/EX6-rule-100300-event.png"><img src="screenshots/Exercise-06/EX6-rule-100300-event.png" width="400" alt="Rule 100300 event detail"></a><br><sub>Rule 100300 event detail</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-06/EX6-rule-100300-event-2.png"><img src="screenshots/Exercise-06/EX6-rule-100300-event-2.png" width="400" alt="Rule 100300 event detail (continued)"></a><br><sub>Rule 100300 event detail (continued)</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-06/EX6-schtask-attack.png"><img src="screenshots/Exercise-06/EX6-schtask-attack.png" width="400" alt="Scheduled task created on the victim"></a><br><sub>Scheduled task created on the victim</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-06/EX6-schtask-sysmon.png"><img src="screenshots/Exercise-06/EX6-schtask-sysmon.png" width="400" alt="Scheduled task in Sysmon (no built-in alert)"></a><br><sub>Scheduled task in Sysmon (no built-in alert)</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-06/EX6-rule-100400-event.png"><img src="screenshots/Exercise-06/EX6-rule-100400-event.png" width="400" alt="Rule 100400 event detail"></a><br><sub>Rule 100400 event detail</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-06/EX6-rule-100400-event-2.png"><img src="screenshots/Exercise-06/EX6-rule-100400-event-2.png" width="400" alt="Rule 100400 event detail (continued)"></a><br><sub>Rule 100400 event detail (continued)</sub></td>
  </tr>
</table>

</details>

---

## Exercise 7: Attack Timeline and Alert Triage

**Attack timeline:** ran a short chain (recon, new local account, Run key, scheduled task) and filtered Wazuh to level 10+ alerts on the victim. The custom rules turn the serious steps into a readable story, oldest first.

**Alert triage:** investigated three unexpected built-in alerts and documented a verdict for each:
- Two **false positives**: a PowerShell execution-policy test file (rule 92213) and a Windows compatibility-database task run by the system (rule 92058)
- One **true-positive activity** whose built-in rule description was misleading

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-07/EX7-attack-timeline.png"><img src="screenshots/Exercise-07/EX7-attack-timeline.png" width="400" alt="Attack timeline (level 10+)"></a><br><sub>Attack timeline (level 10+)</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-07/EX7-attack-chain.png"><img src="screenshots/Exercise-07/EX7-attack-chain.png" width="400" alt="Attack chain on the victim"></a><br><sub>Attack chain on the victim</sub></td>
  </tr>
</table>
<details>
<summary><b>More screenshots</b> (8)</summary>
<br>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-07/EX7-fp-92213.png"><img src="screenshots/Exercise-07/EX7-fp-92213.png" width="400" alt="False positive: rule 92213"></a><br><sub>False positive: rule 92213</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-07/EX7-fp-92213-2.png"><img src="screenshots/Exercise-07/EX7-fp-92213-2.png" width="400" alt="Rule 92213 detail"></a><br><sub>Rule 92213 detail</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-07/EX7-fp-92058.png"><img src="screenshots/Exercise-07/EX7-fp-92058.png" width="400" alt="False positive: rule 92058"></a><br><sub>False positive: rule 92058</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-07/EX7-fp-92058-2.png"><img src="screenshots/Exercise-07/EX7-fp-92058-2.png" width="400" alt="Rule 92058 detail"></a><br><sub>Rule 92058 detail</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-07/EX7-alert-92041.png"><img src="screenshots/Exercise-07/EX7-alert-92041.png" width="400" alt="Rule 92041 alert"></a><br><sub>Rule 92041 alert</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-07/EX7-alert-92041-2.png"><img src="screenshots/Exercise-07/EX7-alert-92041-2.png" width="400" alt="Rule 92041 detail"></a><br><sub>Rule 92041 detail</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-07/EX7-rule-92041-regex.png"><img src="screenshots/Exercise-07/EX7-rule-92041-regex.png" width="400" alt="Rule 92041 logic"></a><br><sub>Rule 92041 logic</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-07/EX7-cleanup.png"><img src="screenshots/Exercise-07/EX7-cleanup.png" width="400" alt="Cleanup"></a><br><sub>Cleanup</sub></td>
  </tr>
</table>

</details>

---

## Exercise 8: Lateral Movement, Tool Transfer and Alert Tuning

Two new attack detections from the Kali attacker, tuning out the false positives found earlier, and a real troubleshooting case where alerts went missing.

### 8.1 Lateral movement over SMB (T1021)

**Attack:** from SOC-Kali (10.10.10.130) I used `netexec` (nxc) to authenticate to SOC-Win11 over SMB (port 445) with valid credentials for `socadmin`.

**What Windows logged:** Event ID **4624** (successful logon) with **Logon Type 3** (network logon) and the Kali IP as the source address.

**Detection:** built-in rule 92657 fired but did not clearly flag lateral movement. Custom child rule 100500 raises network logons to level 12 and maps them to MITRE ATT&CK:

```xml
<rule id="100500" level="12">
  <if_sid>92657</if_sid>
  <field name="win.eventdata.logonType">^3$</field>
  <description>Custom SOC rule: network logon (type 3) - possible lateral movement</description>
  <mitre>
    <id>T1021</id>
  </mitre>
</rule>
```

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-kali-login-success.png"><img src="screenshots/Exercise-08/EX8-kali-login-success.png" width="400" alt="Successful SMB login from Kali"></a><br><sub>Successful SMB login from Kali</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-rule-100500-dashboard.png"><img src="screenshots/Exercise-08/EX8-rule-100500-dashboard.png" width="400" alt="Custom rule 100500 firing"></a><br><sub>Custom rule 100500 firing</sub></td>
  </tr>
</table>
<details>
<summary><b>More screenshots</b> (5)</summary>
<br>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-kali-bruteforce.png"><img src="screenshots/Exercise-08/EX8-kali-bruteforce.png" width="400" alt="SMB authentication attempts from Kali"></a><br><sub>SMB authentication attempts from Kali</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-4624-rule92657.png"><img src="screenshots/Exercise-08/EX8-4624-rule92657.png" width="400" alt="Event 4624 caught by built-in rule 92657"></a><br><sub>Event 4624 caught by built-in rule 92657</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-wazuh-remote-logon.png"><img src="screenshots/Exercise-08/EX8-wazuh-remote-logon.png" width="400" alt="Remote logon in Wazuh"></a><br><sub>Remote logon in Wazuh</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-rule-100500-event.png"><img src="screenshots/Exercise-08/EX8-rule-100500-event.png" width="400" alt="Rule 100500 event detail"></a><br><sub>Rule 100500 event detail</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-rule-100500-ipaddress.png"><img src="screenshots/Exercise-08/EX8-rule-100500-ipaddress.png" width="400" alt="Source IP of the attacker"></a><br><sub>Source IP of the attacker</sub></td>
  </tr>
</table>

</details>

### 8.2 PowerShell web download (T1105)

**Attack:** used `Invoke-WebRequest` on the victim to download a file, simulating an attacker pulling tools onto a compromised host.

**What Sysmon logged:** Event ID **1** (process creation, with the full command line) and Event ID **3** (network connection).

**Detection gap:** built-in rule 92027 only alerted at **level 4**, easy to miss in a busy SOC. Rule 100600 raises it to level 12.

**Lesson learned:** my first version used `<if_group>sysmon_event1</if_group>` and never fired. Wazuh evaluates rules as a tree: once an event matches 92027, only children of 92027 are checked. Changing the parent to `<if_sid>92027</if_sid>` fixed it.

```xml
<rule id="100600" level="12">
  <if_sid>92027</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(Invoke-WebRequest|iwr|DownloadString|DownloadFile|wget|curl)</field>
  <description>Custom SOC rule: Powershell web download - possible tool transfer</description>
  <mitre>
    <id>T1105</id>
  </mitre>
</rule>
```

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-ps-download-attack.png"><img src="screenshots/Exercise-08/EX8-ps-download-attack.png" width="400" alt="PowerShell download on the victim"></a><br><sub>PowerShell download on the victim</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-rule-100600-dashboard.png"><img src="screenshots/Exercise-08/EX8-rule-100600-dashboard.png" width="400" alt="Custom rule 100600 firing"></a><br><sub>Custom rule 100600 firing</sub></td>
  </tr>
</table>
<details>
<summary><b>More screenshots</b> (4)</summary>
<br>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-ps-download-sysmon-1.png"><img src="screenshots/Exercise-08/EX8-ps-download-sysmon-1.png" width="400" alt="Sysmon Event 1: process creation"></a><br><sub>Sysmon Event 1: process creation</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-ps-download-sysmon-3.png"><img src="screenshots/Exercise-08/EX8-ps-download-sysmon-3.png" width="400" alt="Sysmon Event 3: network connection"></a><br><sub>Sysmon Event 3: network connection</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-rule-100600-event-1.png"><img src="screenshots/Exercise-08/EX8-rule-100600-event-1.png" width="400" alt="Rule 100600 event detail"></a><br><sub>Rule 100600 event detail</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-rule-100600-event-2.png"><img src="screenshots/Exercise-08/EX8-rule-100600-event-2.png" width="400" alt="Rule 100600 event detail (continued)"></a><br><sub>Rule 100600 event detail (continued)</sub></td>
  </tr>
</table>

</details>

### 8.3 Tuning false positives

Two built-in rules kept firing on normal Windows activity:

| Rule | Level | Benign cause |
|---|---|---|
| 92213 "Executable file dropped in folder commonly used by malware" | 15 | PowerShell creates a temporary `__PSScriptPolicyTest_*.ps1` file every time it starts, to check execution policy |
| 92058 "Application Compatibility Database launched" | 12 | Windows' Program Compatibility Assistant service (svchost.exe `-s PcaSvc`) runs `sdbinst.exe -m -bg` as routine maintenance |

**Approach:** before suppressing anything, I opened each alert and checked the exact field values (file name, image, command line, parent process). Not every 92213 alert was the PowerShell test file, so a broad suppression would have hidden real activity. I wrote **level 0 child rules** (level 0 = no alert) that only match the exact benign pattern:

```xml
<rule id="100700" level="0">
  <if_sid>92213</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe$</field>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)\\__PSScriptPolicyTest_[a-z0-9]+\.[a-z0-9]+\.ps1$</field>
  <description>Suppressed FP: PowerShell execution policy test file (benign)</description>
</rule>

<rule id="100710" level="0">
  <if_sid>92058</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)^C:\\Windows\\System32\\sdbinst\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)sdbinst\.exe"?\s+-m\s+-bg\s*$</field>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)^C:\\Windows\\System32\\svchost\.exe$</field>
  <description>Suppressed FP: sdbinst -m -bg run by PcaSvc (benign)</description>
</rule>
```

**Why these are narrow:**
- 100700 requires **both** the PowerShell process **and** the exact test-file name pattern. Malware dropping a file with that name from another process still alerts.
- 100710 requires the exact command line **and** svchost.exe as the parent. `sdbinst` is a known persistence technique (T1546.011), so running it any other way must still alert.

| Test | Expected | Result |
|---|---|---|
| Opened PowerShell several times | No 92213 alerts | 14 `__PSScriptPolicyTest` events reached the manager, **0 alerts** |
| Ran `sdbinst.exe -m -bg` from an admin PowerShell (negative test) | 92058 still alerts | **92058 fired at level 12** |

The negative test matters: it proves the suppression did not create a blind spot.

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-14-FP-alerts-before.png"><img src="screenshots/Exercise-08/EX8-14-FP-alerts-before.png" width="400" alt="False positive alerts before tuning"></a><br><sub>False positive alerts before tuning</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-16-FP-suppressed-proof.png"><img src="screenshots/Exercise-08/EX8-16-FP-suppressed-proof.png" width="400" alt="False positives suppressed"></a><br><sub>False positives suppressed</sub></td>
  </tr>
</table>
<details>
<summary><b>More screenshots</b> (2)</summary>
<br>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-15-rules-loaded.png"><img src="screenshots/Exercise-08/EX8-15-rules-loaded.png" width="400" alt="Rules loaded without errors"></a><br><sub>Rules loaded without errors</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-17-sdbinst-still-alerts.png"><img src="screenshots/Exercise-08/EX8-17-sdbinst-still-alerts.png" width="400" alt="Negative test: sdbinst from PowerShell still alerts"></a><br><sub>Negative test: sdbinst from PowerShell still alerts</sub></td>
  </tr>
</table>

</details>

### 8.4 Investigation: "no alerts" does not mean "no activity"

During the negative test, the expected 92058 alert never appeared. Instead of assuming my rule was wrong, I worked through the log pipeline step by step:

1. **Endpoint:** queried Sysmon directly on SOC-Win11 with `Get-WinEvent`. The `sdbinst` process creation **was** logged, so Sysmon was fine.
2. **Rule logic:** read built-in rule 92058 in `/var/ossec/ruleset/rules/0800-sysmon_id_1.xml`. It should have matched.
3. **Manager:** temporarily enabled `logall_json` to archive every event received. The archive contained **zero** Windows EventChannel events from the agent, only SCA and rootcheck data.
4. **Root cause:** the Wazuh agent service on the victim had stopped after a failed restart. The manager still showed it as Active for a while, but no Windows logs were being collected.
5. **Fix:** started the agent service again, confirmed in the agent log that it was reading the Security, System and Sysmon channels, confirmed events were arriving in the archive, and re-ran both tests.

My first "suppression works" result was therefore not valid evidence, because no events were arriving at that time. I repeated the test after the fix to get real proof.

I also found that the vulnerability detection module was repeatedly crashing `wazuh-modulesd` (feed download failure), which made the dashboard lose its API connection. It is disabled in this lab since it is not needed for attack detection. Verification during the outage was done over SSH using `alerts.json` and `archives.json`.

**Key takeaway:** before trusting the absence of alerts, confirm that the logs are actually reaching the SIEM.

### 8.5 Attack timeline

On 13 Oct, a full chain (discovery, then account creation, Run key and scheduled task persistence) was detected within about four minutes. Together with this exercise, six custom rules covered six MITRE techniques (see the [detection summary](#-detection-summary)).

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-18-mitre-overview.png"><img src="screenshots/Exercise-08/EX8-18-mitre-overview.png" width="400" alt="MITRE ATT&CK overview"></a><br><sub>MITRE ATT&CK overview</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-08/EX8-19-attack-timeline.png"><img src="screenshots/Exercise-08/EX8-19-attack-timeline.png" width="400" alt="Attack timeline"></a><br><sub>Attack timeline</sub></td>
  </tr>
</table>

---

## Exercise 9: Linux SSH Brute Force and Successful Login

**Scenario:** an attacker on Kali (10.10.10.130) brute-forced SSH on the Ubuntu 26.04 Wazuh server, logged in with the cracked password, and tried to escalate to root. A lab-only user (`testuser`) was used so no real credentials appear anywhere.

**Attack timeline (UTC):**
- 15:35:04 to 15:35:11: hydra tried 16 passwords from 4 parallel source ports
- 15:35:12: password cracked
- 15:36:42: attacker logged in over SSH and ran `whoami`, `id`, `hostname`, `sudo -l`

**Detections:**

| Rule | Level | Detects | MITRE |
|---|---|---|---|
| 5902 / 5901 | 8 | New user / group created | T1136 |
| 5760 / 5503 | 5 | Failed SSH password | T1110.001 |
| 5763 / 2502 | 10 | SSH brute force | T1110 |
| 40112 | 12 | Failures followed by a success | T1078, T1110 |
| **100800 (custom)** | **14** | **SSH brute force that SUCCEEDED** | **T1110.001, T1078** |

**Custom rule 100800:** child of built-in rule 40112, matches `Accepted password`, raises the alert to level 14. The first version used `<match>sshd</match>` and never fired: Wazuh's predecoder moves the program name (`sshd-session`) into its own field, and `<match>` only checks the remaining message. Fixed and re-tested.

```xml
<rule id="100800" level="14">
  <if_sid>40112</if_sid>
  <match>Accepted password</match>
  <description>SSH brute force SUCCEEDED: $(dstuser) logged in from $(srcip) after multiple failures</description>
  <mitre>
    <id>T1110.001</id>
    <id>T1078</id>
  </mitre>
</rule>
```

**Findings:**
- **Visibility gap:** sudo-rs on Ubuntu 26.04 did not log denied `sudo` attempts by a non-sudoer, so no alert was possible. Planned fix: auditd.
- A later login with the stolen password (no failures first) produced only a level 3 alert: stolen credentials look like normal logins.
- Dashboard DQL `agent.id:000` returns nothing (parsed as a number); `agent.name:soc-wazuh` works.
- Server logs are UTC while the dashboard shows local time (UTC+2), so timelines must state the timezone.

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-03-hydra-success.png"><img src="screenshots/Exercise-09/EX9-03-hydra-success.png" width="400" alt="hydra cracks the password"></a><br><sub>hydra cracks the password</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-05-wazuh-ssh-bruteforce-events.png"><img src="screenshots/Exercise-09/EX9-05-wazuh-ssh-bruteforce-events.png" width="400" alt="SSH brute force events in Wazuh"></a><br><sub>SSH brute force events in Wazuh</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-09-rule-100800-mitre.png"><img src="screenshots/Exercise-09/EX9-09-rule-100800-mitre.png" width="400" alt="Rule 100800 with MITRE mapping"></a><br><sub>Rule 100800 with MITRE mapping</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-10-sudo-visibility-gap.png"><img src="screenshots/Exercise-09/EX9-10-sudo-visibility-gap.png" width="400" alt="sudo visibility gap"></a><br><sub>sudo visibility gap</sub></td>
  </tr>
</table>
<details>
<summary><b>More screenshots</b> (13)</summary>
<br>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-01-linux-auth-log-grep.png"><img src="screenshots/Exercise-09/EX9-01-linux-auth-log-grep.png" width="400" alt="auth.log on the server"></a><br><sub>auth.log on the server</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-01b-successful-logins-baseline.png"><img src="screenshots/Exercise-09/EX9-01b-successful-logins-baseline.png" width="400" alt="Baseline of successful logins"></a><br><sub>Baseline of successful logins</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-02-linux-new-user-alert.png"><img src="screenshots/Exercise-09/EX9-02-linux-new-user-alert.png" width="400" alt="New Linux user alert"></a><br><sub>New Linux user alert</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-02b-new-user-dashboard.png"><img src="screenshots/Exercise-09/EX9-02b-new-user-dashboard.png" width="400" alt="New user on the dashboard"></a><br><sub>New user on the dashboard</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-02c-new-user-alert-details.png"><img src="screenshots/Exercise-09/EX9-02c-new-user-alert-details.png" width="400" alt="New user alert details"></a><br><sub>New user alert details</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-04-attacker-ssh-session.png"><img src="screenshots/Exercise-09/EX9-04-attacker-ssh-session.png" width="400" alt="Attacker SSH session"></a><br><sub>Attacker SSH session</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-05a-attack-overview-dashboard.png"><img src="screenshots/Exercise-09/EX9-05a-attack-overview-dashboard.png" width="400" alt="Attack overview dashboard"></a><br><sub>Attack overview dashboard</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-06-auth-log-timeline.png"><img src="screenshots/Exercise-09/EX9-06-auth-log-timeline.png" width="400" alt="auth.log timeline"></a><br><sub>auth.log timeline</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-07-rule-100800-xml.png"><img src="screenshots/Exercise-09/EX9-07-rule-100800-xml.png" width="400" alt="Rule 100800 XML"></a><br><sub>Rule 100800 XML</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-08-rule-100800-fired.png"><img src="screenshots/Exercise-09/EX9-08-rule-100800-fired.png" width="400" alt="Rule 100800 fired"></a><br><sub>Rule 100800 fired</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-08a-rule-100800-cli-proof.png"><img src="screenshots/Exercise-09/EX9-08a-rule-100800-cli-proof.png" width="400" alt="Rule 100800 proof from the CLI"></a><br><sub>Rule 100800 proof from the CLI</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-10a-attacker-sudo-attempt.png"><img src="screenshots/Exercise-09/EX9-10a-attacker-sudo-attempt.png" width="400" alt="Attacker sudo attempt"></a><br><sub>Attacker sudo attempt</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-09/EX9-11-user-deleted-alert.png"><img src="screenshots/Exercise-09/EX9-11-user-deleted-alert.png" width="400" alt="Lab user deleted alert"></a><br><sub>Lab user deleted alert</sub></td>
  </tr>
</table>

</details>

---

## Exercise 10: File Integrity Monitoring and Startup Persistence

**Goal:** detect tampering of sensitive files and persistence through the Windows Startup folder, and close the gaps left by Wazuh's built-in FIM rules.

**What I did:**
- Enabled Wazuh FIM (syscheck) in **whodata** mode on the Windows 11 endpoint for a sensitive `C:\FIM-Test\Finance` folder (with `report_changes` for content diffs) and both Windows Startup folders.
- Added, modified and deleted files and verified built-in rules 554, 550 and 553. Whodata captured the user (`socadmin`), the process (`powershell.exe` and its PID) and the exact line added to the file.
- Simulated persistence by dropping a harmless `WindowsUpdateHelper.bat` into the user's Startup folder (T1547.001).
- Cross-checked with Sysmon (Event 11) to compare endpoint telemetry with FIM.

**Findings:**

| Activity | Built-in rule | Level | MITRE |
|---|---|---|---|
| File added to the Startup folder | 554 | 5 | none |
| Finance file modified | 550 | 7 | T1565.001 |
| Finance file deleted | 553 | 7 | T1070.004, T1485 |

**Detection gap:** the persistence file raised only a level 5 alert with no MITRE mapping, and tampering with a sensitive Finance file looked the same as any routine file change (level 7). The modify, delete and Startup drop all came from the same PowerShell process ID, which ties them into one attack chain.

**Custom rules:**

```xml
<group name="local,syscheck,fim,">

  <rule id="100900" level="10">
    <if_sid>550, 553</if_sid>
    <field name="file" type="pcre2">(?i)c:\\fim-test\\finance\\</field>
    <description>FIM: Sensitive Finance file modified or deleted: $(file)</description>
    <mitre>
      <id>T1565.001</id>
    </mitre>
  </rule>

  <rule id="100910" level="12">
    <if_sid>554</if_sid>
    <field name="file" type="pcre2">(?i)\\start menu\\programs\\startup\\</field>
    <description>FIM: File added to Windows Startup folder - possible persistence: $(file)</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

</group>
```

**Result:**

| Activity | Before | After |
|---|---|---|
| Finance file modified or deleted | 550 / 553, level 7 | **100900, level 10** |
| File added to a Startup folder | 554, level 5, no MITRE | **100910, level 12, T1547.001** |

Both rules fired with the full file path in the description. The Startup alert now appears under "Level 12 or above" and in the MITRE ATT&CK view as Persistence.

**Troubleshooting and lessons:**
- **Dashboard field names are not rule field names.** The dashboard shows `syscheck.path`, but inside a rule the FIM path field is `file`. My first version of rule 100900 never fired until I fixed this (the description variable too: `$(file)`).
- **Slow lab VM:** `systemctl restart wazuh-manager` timed out and left an orphaned `wazuh-apid`. Running `wazuh-control stop` and then `systemctl start` worked reliably.
- **FIM and Sysmon complement each other.** A stray copy of the test file created in `C:\` was missed by FIM (folder not monitored) but caught by Sysmon (rule 92203). Sysmon flagged the Startup file (rule 92201, level 9) but mapped it to T1105/T1059, not persistence.
- **Endpoint crash investigation:** the Windows 11 VM blue-screened (bugcheck 0x124) several times during the lab. Using Event IDs 41, 6008 and 1001 I confirmed the crashes and ruled out the FIM config, nested virtualization, the CPU layout and host hardware (no host WHEA errors). Wazuh raised **no alert** for the crashes: a second detection gap. Event ID 1001 exists in two logs (System bugcheck vs Application Windows Error Reporting), so channel and provider must be checked, not just the Event ID.

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-07a.png"><img src="screenshots/Exercise-10/EX10-07a.png" width="400" alt="Startup drop: built-in rule 554, level 5, no MITRE"></a><br><sub>Startup drop: built-in rule 554, level 5, no MITRE</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-10.png"><img src="screenshots/Exercise-10/EX10-10.png" width="400" alt="Custom rule 100910: level 12, T1547.001"></a><br><sub>Custom rule 100910: level 12, T1547.001</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-05b.png"><img src="screenshots/Exercise-10/EX10-05b.png" width="400" alt="Whodata: user, process and file diff"></a><br><sub>Whodata: user, process and file diff</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-11.png"><img src="screenshots/Exercise-10/EX10-11.png" width="400" alt="Custom FIM rules in the MITRE view"></a><br><sub>Custom FIM rules in the MITRE view</sub></td>
  </tr>
</table>
<details>
<summary><b>More screenshots</b> (17)</summary>
<br>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-01.png"><img src="screenshots/Exercise-10/EX10-01.png" width="400" alt="Default agent FIM configuration"></a><br><sub>Default agent FIM configuration</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-02.png"><img src="screenshots/Exercise-10/EX10-02.png" width="400" alt="New FIM directories in ossec.conf"></a><br><sub>New FIM directories in ossec.conf</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-03.png"><img src="screenshots/Exercise-10/EX10-03.png" width="400" alt="Whodata engine started"></a><br><sub>Whodata engine started</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-04.png"><img src="screenshots/Exercise-10/EX10-04.png" width="400" alt="Rule 554: file added, with whodata"></a><br><sub>Rule 554: file added, with whodata</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-05a.png"><img src="screenshots/Exercise-10/EX10-05a.png" width="400" alt="Rule 550: Finance file modified"></a><br><sub>Rule 550: Finance file modified</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-06a.png"><img src="screenshots/Exercise-10/EX10-06a.png" width="400" alt="Rule 553: file deleted"></a><br><sub>Rule 553: file deleted</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-06b.png"><img src="screenshots/Exercise-10/EX10-06b.png" width="400" alt="Rule 553 MITRE mapping"></a><br><sub>Rule 553 MITRE mapping</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-07b.png"><img src="screenshots/Exercise-10/EX10-07b.png" width="400" alt="Startup drop alert details"></a><br><sub>Startup drop alert details</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-07c.png"><img src="screenshots/Exercise-10/EX10-07c.png" width="400" alt="Sysmon Event 11 alerts"></a><br><sub>Sysmon Event 11 alerts</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-08.png"><img src="screenshots/Exercise-10/EX10-08.png" width="400" alt="Custom rules 100900 and 100910"></a><br><sub>Custom rules 100900 and 100910</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-09.png"><img src="screenshots/Exercise-10/EX10-09.png" width="400" alt="Custom rule 100900: level 10"></a><br><sub>Custom rule 100900: level 10</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-12.png"><img src="screenshots/Exercise-10/EX10-12.png" width="400" alt="Cleanup: Startup folder empty"></a><br><sub>Cleanup: Startup folder empty</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-TS-01-crash-events.png"><img src="screenshots/Exercise-10/EX10-TS-01-crash-events.png" width="400" alt="Crash events (41, 6008, 1001)"></a><br><sub>Crash events (41, 6008, 1001)</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-TS-02-crash-events.png"><img src="screenshots/Exercise-10/EX10-TS-02-crash-events.png" width="400" alt="Crash events (continued)"></a><br><sub>Crash events (continued)</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-TS-03.png"><img src="screenshots/Exercise-10/EX10-TS-03.png" width="400" alt="No Wazuh alert for the crashes"></a><br><sub>No Wazuh alert for the crashes</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-TS-04.png"><img src="screenshots/Exercise-10/EX10-TS-04.png" width="400" alt="VM CPU layout change"></a><br><sub>VM CPU layout change</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-10/EX10-TS-05.png"><img src="screenshots/Exercise-10/EX10-TS-05.png" width="400" alt="Side channel mitigations disabled"></a><br><sub>Side channel mitigations disabled</sub></td>
  </tr>
</table>

</details>

---

## Exercise 11: Defense Evasion and Endpoint Health

**Goal:** detect the moves an attacker makes to blind the SOC after gaining access, clearing the event logs, stopping security tools, and crashing or powering off the endpoint, and decide for each whether a custom rule is actually warranted.

**Method:** before writing any rule I verified the log pipeline with archives (`logall_json`), so I could tell "the event never reached the manager" apart from "the event arrived but no rule matched". Where the built-in coverage was already adequate or the data never arrived, I documented that instead of adding a rule, so every rule I ship corresponds to data that really reaches the SIEM.

### 11.1 Event log clearing (T1070.001)

**Attack:** cleared the Security log (`wevtutil cl Security`) and the Sysmon log, which Windows itself records.

| Cleared | Event | Built-in rule | Level | MITRE |
|---|---|---|---|---|
| Security log | 1102 | 63103 "The audit log was cleared" | 5 | T1070 |
| Sysmon log | 104 | 63104 "A Windows log file was cleared" | 5 | T1070 |

**Gap:** both fired but only at **level 5**, and mapped to the parent technique T1070, not the sub-technique. The account that cleared the log (`socadmin`) was visible in the alert.

**Custom rule 100930:** child of 63103 / 63104, raises both to level 12 and maps them to T1070.001.

```xml
<group name="local,windows,defense_evasion,">
  <rule id="100930" level="12">
    <if_sid>63103,63104</if_sid>
    <field name="win.system.eventID">^1102$|^104$</field>
    <description>Windows event log cleared ($(win.system.channel)) - attacker clearing tracks (Event $(win.system.eventID))</description>
    <mitre>
      <id>T1070.001</id>
    </mitre>
  </rule>
</group>
```

**Result:** both log-clear events fired rule 100930 at level 12, shown in the MITRE view as "Clear Windows Event Logs".

### 11.2 Stopping Sysmon (T1562.001), a positive finding

I tried to stop the Sysmon service four ways: `Stop-Service`, `sc.exe stop`, `Stop-Process -Force`, and PsExec running as SYSTEM. **All were denied.** Sysmon64 is a self-protected service that cannot be stopped from Administrator or even SYSTEM; an attacker would have to use Sysmon's own `-u` unload or a config reload. I documented this as a positive finding (endpoint telemetry cannot be trivially killed) rather than forcing it, and did not write the planned Sysmon-stop rule, because the "service stopped" event never occurred.

### 11.3 Stopping the Wazuh agent (T1562.001)

Stopping the agent is the most dangerous move: with the agent down, the SOC is blind to that endpoint.

- Built-in rule **506 "Wazuh agent stopped"** fired, with the correct MITRE mapping (T1562.001), but only at **level 3**. Gap: the severity is far too low for an event that blinds the SOC. A tuned child of rule 506 (level 12) is a planned follow-up.
- **Second finding:** a System event written *while the agent was stopped* never reached the manager, and was not recovered after the agent restarted. The agent does not replay Windows EventChannel events it missed while down, so anything that happens during an agent outage is a permanent blind spot.

### 11.4 Unexpected shutdown and crash (T1529), a visibility gap

During this exercise the Windows 11 VM crashed twice (the recurring 0x124 WHEA bugcheck) and was hard-powered-off once. Windows logged the expected System events: **41 (Kernel-Power)** and **6008 (unexpected shutdown)**.

But Wazuh showed **0 alerts**, and the archives contained **no 41/6008 events at all**, even though the pipeline was confirmed live at the same moment (a test event written seconds earlier did reach the archives). The reason: these events are written just before shutdown or at the next boot, while the agent is down, and the agent never recovers them, the same behaviour as the missed event in 11.3.

**Decision:** I did **not** write the planned crash-detection rules. Writing a rule for data that never reaches the manager would be theatre, not detection. Instead this is documented as a **visibility gap**, with possible future fixes: agent-side bookmark persistence, or host/hypervisor-level monitoring that does not depend on the guest's own agent.

**Pipeline lesson (a repeat of Exercise 8):** after a crash the agent showed as "Active" but sent no EventChannel logs; the archive held only SCA and rootcheck data. `Stop-Service` timed out but did stop the service, and `Start-Service` restored the log flow. "Active" is not enough, I verify that real events are actually arriving. On this slow HDD VM the reliable restart is always `wazuh-control stop` (removing a leftover `start-script-lock` directory if present) followed by `systemctl start`, never `restart`.

**Rules shipped this exercise:** 100930 only. The crash and Sysmon-stop rules were deliberately not written, for the reasons above, an honest scope where every rule maps to data that reaches the SIEM.

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-05%281102%29.png"><img src="screenshots/Exercise-11/EX11-05%281102%29.png" width="400" alt="Security log cleared: built-in 63103, level 5"></a><br><sub>Security log cleared: built-in 63103, level 5</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-14.png"><img src="screenshots/Exercise-11/EX11-14.png" width="400" alt="Rule 100930: level 12, Clear Windows Event Logs"></a><br><sub>Rule 100930: level 12, Clear Windows Event Logs</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-09.png"><img src="screenshots/Exercise-11/EX11-09.png" width="400" alt="Agent stopped: built-in 506, level 3"></a><br><sub>Agent stopped: built-in 506, level 3</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-12.png"><img src="screenshots/Exercise-11/EX11-12.png" width="400" alt="Crash/shutdown: 0 alerts (visibility gap)"></a><br><sub>Crash/shutdown: 0 alerts (visibility gap)</sub></td>
  </tr>
</table>
<details>
<summary><b>More screenshots</b> (14)</summary>
<br>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-02.png"><img src="screenshots/Exercise-11/EX11-02.png" width="400" alt="Agent log channels (no System query)"></a><br><sub>Agent log channels (no System query)</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-03.png"><img src="screenshots/Exercise-11/EX11-03.png" width="400" alt="Test event reaches archives (pipeline check)"></a><br><sub>Test event reaches archives (pipeline check)</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-04.png"><img src="screenshots/Exercise-11/EX11-04.png" width="400" alt="wevtutil log-clear commands"></a><br><sub>wevtutil log-clear commands</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-06%28104%29.png"><img src="screenshots/Exercise-11/EX11-06%28104%29.png" width="400" alt="Sysmon log cleared: built-in 63104, level 5"></a><br><sub>Sysmon log cleared: built-in 63104, level 5</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-07.png"><img src="screenshots/Exercise-11/EX11-07.png" width="400" alt="Sysmon stop denied, even as SYSTEM"></a><br><sub>Sysmon stop denied, even as SYSTEM</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-10.png"><img src="screenshots/Exercise-11/EX11-10.png" width="400" alt="Event written while agent stopped"></a><br><sub>Event written while agent stopped</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-10b.png"><img src="screenshots/Exercise-11/EX11-10b.png" width="400" alt="That event never recovered (blind spot)"></a><br><sub>That event never recovered (blind spot)</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-11.png"><img src="screenshots/Exercise-11/EX11-11.png" width="400" alt="Windows logged crash events 41 and 6008"></a><br><sub>Windows logged crash events 41 and 6008</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-13.png"><img src="screenshots/Exercise-11/EX11-13.png" width="400" alt="Crash events never reached the archives"></a><br><sub>Crash events never reached the archives</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-15.png"><img src="screenshots/Exercise-11/EX11-15.png" width="400" alt="Rule 100930 events: both log clears, level 12"></a><br><sub>Rule 100930 events: both log clears, level 12</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-16%20%28cleanup%20proof%29.png"><img src="screenshots/Exercise-11/EX11-16%20%28cleanup%20proof%29.png" width="400" alt="Cleanup: tools running, PsExec removed"></a><br><sub>Cleanup: tools running, PsExec removed</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-01.png"><img src="screenshots/Exercise-11/EX11-01.png" width="400" alt="Crash watch at lab start"></a><br><sub>Crash watch at lab start</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-03a.png"><img src="screenshots/Exercise-11/EX11-03a.png" width="400" alt="Test event created on the endpoint"></a><br><sub>Test event created on the endpoint</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-11/EX11-TS-02.png"><img src="screenshots/Exercise-11/EX11-TS-02.png" width="400" alt="Pipeline stall after crash: archives missing EventChannel"></a><br><sub>Pipeline stall after crash: archives missing EventChannel</sub></td>
  </tr>
</table>

</details>

---

## Exercise 12: Endpoint Stability Troubleshooting (0x124 WHEA Crash)

**Problem:** The Windows 11 endpoint kept crashing with bugcheck `0x124` (WHEA_UNCORRECTABLE_ERROR). Every crash stopped the Wazuh agent and interrupted detection work, and Exercise 11 showed that events from a crashed endpoint never reach the SIEM. A stable endpoint is a prerequisite for detection.

**Approach:** Change one variable at a time, test each hypothesis with a repeatable test, and record every result in a crash log.

### 1. Ruling out the obvious suspect: heat

The host fan spiked before each crash, so CPU heat was the first hypothesis. With HWiNFO64 on the host, I ran CPU stress tests inside the VM with no settings changed:

| Test | Conditions | Max CPU temp | Crash |
|---|---|---|---|
| 1 | Endpoint only, 5 min | 102 C | No |
| 2 | Endpoint + Wazuh, 5 min | 100 C | No |
| 3 | Endpoint + Wazuh, 45 min | 100 C | No |

About 55 minutes at the CPU's thermal limit, host WHEA errors 0, and no crash. **Heat alone did not reproduce the fault**, so it was not the root cause.

### 2. Building a crash timeline from the Event Log

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,1001,6005,6008; StartTime='2026-11-01'} |
  Sort-Object TimeCreated | Format-Table TimeCreated, Id, ProviderName -AutoSize
```

Event 6005 (boot), 41 (Kernel-Power), 6008 (unexpected shutdown) and 1001 (BugCheck `0x124`, parameter 1 = `0x10`, dump saved) gave two crashes on one day, roughly 20 and 40 minutes after boot.

### 3. Root cause from the crash dump (WinDbg)

`!analyze -v` on `MEMORY.DMP`:

- **Arg1 = `0x10`: Device Driver Error.** The error was reported by a driver, not by a CPU machine check.
- The crash stack, read bottom to top:

```
storport!RaidHierarchicalResetWorkRoutine     <- disk stopped responding, reset started
stornvme!NVMeHwResetBus / NVMeControllerReset  <- virtual NVMe controller reset
storport!StorpMarkDeviceFailed                 <- reset failed, device marked failed
storport!StorpWheaReportError
nt!WheaReportFatalHwErrorDeviceDriverEx        <- reported as a fatal hardware error
nt!KeBugCheckEx                                <- 0x124
```

The `GenuineIntel.sys` failure bucket is a misleading default label; the real actor is the NVMe storage driver.

**Confirmation:** the System log showed `stornvme` **Event 129** (reset to device) on three separate days before the crashes, so the virtual disk had been timing out repeatedly.

**Root cause:** the endpoint's virtual disk used a virtual NVMe controller and its files sat on the host's slow HDD. Under load, disk I/O stalled long enough for Windows to reset the controller; when the reset failed, the driver raised a fatal WHEA error. This also explains why the CPU stress tests never crashed it: they did not touch the disk. The Wazuh server VM, on the same HDD but with a SATA virtual disk, never crashed.

### 4. Fix (one change only)

Moved only the endpoint VM from the HDD to the host SSD (`robocopy`, 130 files / 86 GB, 0 failed) and re-registered it in VMware with *I Moved It*, so its identity, IP and Wazuh agent stayed the same. No other VM setting was changed, so the disk is the only variable.

### 5. Validation

With Wazuh running, a 30-minute write-through disk test wrote about **574 GB** (2295 blocks of 256 MB):

- No crash, host WHEA errors 0
- **0 `stornvme` Event 129** since boot

The fix will keep being monitored over the next lab sessions before the old HDD copy is removed.

### Screenshots

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-06-stress3-45min-no-crash.png"><img src="screenshots/Exercise-12/EX12-06-stress3-45min-no-crash.png" width="400" alt="45-minute CPU stress, no crash"></a><br><sub>45-minute CPU stress, no crash</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-08-windbg-analyze-device-driver-error.png"><img src="screenshots/Exercise-12/EX12-08-windbg-analyze-device-driver-error.png" width="400" alt="WinDbg: Arg1 0x10, Device Driver Error"></a><br><sub>WinDbg: Arg1 0x10, Device Driver Error</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-09-windbg-stack-stornvme.png"><img src="screenshots/Exercise-12/EX12-09-windbg-stack-stornvme.png" width="400" alt="Crash stack: stornvme reset, WHEA fatal, 0x124"></a><br><sub>Crash stack: stornvme reset, WHEA fatal, 0x124</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-11-eventlog-stornvme-129-resets.png"><img src="screenshots/Exercise-12/EX12-11-eventlog-stornvme-129-resets.png" width="400" alt="stornvme Event 129 disk resets before the fix"></a><br><sub>stornvme Event 129 disk resets before the fix</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-15-disk-test-30min-ssd-no-crash.png"><img src="screenshots/Exercise-12/EX12-15-disk-test-30min-ssd-no-crash.png" width="400" alt="After the fix: 30-minute disk test, no crash"></a><br><sub>After the fix: 30-minute disk test, no crash</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-16-event129-zero-after-ssd.png"><img src="screenshots/Exercise-12/EX12-16-event129-zero-after-ssd.png" width="400" alt="After the fix: 0 disk resets since boot"></a><br><sub>After the fix: 0 disk resets since boot</sub></td>
  </tr>
</table>

<details>
<summary>More screenshots</summary>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-01-boot-101C.png"><img src="screenshots/Exercise-12/EX12-01-boot-101C.png" width="400" alt="Boot temperature, host WHEA 0"></a><br><sub>Boot temperature, host WHEA 0</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-02-stress1-no-crash.png"><img src="screenshots/Exercise-12/EX12-02-stress1-no-crash.png" width="400" alt="Stress test 1, no crash"></a><br><sub>Stress test 1, no crash</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-03-stress2-wazuh-on-no-crash.png"><img src="screenshots/Exercise-12/EX12-03-stress2-wazuh-on-no-crash.png" width="400" alt="Stress test 2 with Wazuh, no crash"></a><br><sub>Stress test 2 with Wazuh, no crash</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-04-crash-timeline-eventlog.png"><img src="screenshots/Exercise-12/EX12-04-crash-timeline-eventlog.png" width="400" alt="Crash timeline from the Event Log"></a><br><sub>Crash timeline from the Event Log</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-05-bugcheck-0x124-details.png"><img src="screenshots/Exercise-12/EX12-05-bugcheck-0x124-details.png" width="400" alt="BugCheck 0x124 details"></a><br><sub>BugCheck 0x124 details</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-07-windbg-dump-loaded-uptime-20min.png"><img src="screenshots/Exercise-12/EX12-07-windbg-dump-loaded-uptime-20min.png" width="400" alt="Dump loaded, uptime 20 minutes"></a><br><sub>Dump loaded, uptime 20 minutes</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-10-windbg-failure-bucket.png"><img src="screenshots/Exercise-12/EX12-10-windbg-failure-bucket.png" width="400" alt="Failure bucket"></a><br><sub>Failure bucket</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-12-before-move-nvme-on-hdd.png"><img src="screenshots/Exercise-12/EX12-12-before-move-nvme-on-hdd.png" width="400" alt="Before: NVMe disk on HDD"></a><br><sub>Before: NVMe disk on HDD</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-13-robocopy-to-ssd.png"><img src="screenshots/Exercise-12/EX12-13-robocopy-to-ssd.png" width="400" alt="robocopy to SSD, 0 failed"></a><br><sub>robocopy to SSD, 0 failed</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-12/EX12-14-after-move-vm-on-ssd.png"><img src="screenshots/Exercise-12/EX12-14-after-move-vm-on-ssd.png" width="400" alt="After: VM on SSD"></a><br><sub>After: VM on SSD</sub></td>
  </tr>
</table>

</details>

---

## Exercise 13: RDP Brute Force and Successful Remote Logon

**Scenario:** an attacker on Kali (10.10.10.130) brute-forced RDP on the Windows 11 endpoint, logged in with the cracked password to open a real remote desktop, then signed out. A lab-only user (`rdptest`) was used so no real credentials appear anywhere. This is the Windows/RDP counterpart to the Linux SSH detection in Exercise 9.

**Why it matters:** RDP is one of the most attacked services on the internet and a favourite entry point for ransomware. Failed logons are just noise; the alert that matters is the moment a brute force *succeeds* and the attacker is inside.

**Attack:**
- Recon: `nmap -p 3389` confirmed `3389/tcp open ms-wbt-server` (with NLA enabled).
- Brute force: `nxc rdp` with a short wordlist (8 wrong + 1 correct, kept under the 10-attempt lockout) cracked `rdptest:Summer2026!`.
- Login: `xfreerdp3` opened a real RDP desktop as `rdptest`; `whoami` confirmed the session.

**Investigation (confirmed every rule ID on the dashboard, no guessing):**

| Event | Meaning | Built-in rule | Level | MITRE |
|---|---|---|---|---|
| 4625, logon type 3 | Failed logon (NLA checks the password at network level *before* the desktop opens, so failures show as type 3, not 10) | 60122 | 5 | T1110.001 |
| Multiple 4625 | Brute-force correlation | 60204 | 10 | T1110 |
| 4624, logon type 10 | Successful RemoteInteractive (real RDP desktop) | 92653 | 3 | T1021.001 |

**Detection gap:** the same IP produced 8 failures and then a successful RDP login, but that success was only a **level 3** alert (92653), easy to miss in a busy SOC. Unlike SSH (which has built-in rule 40112 for "failures then success"), Windows RDP had no high-severity "brute force succeeded" alert.

**Custom rules:**

```xml
<group name="local,windows,authentication,">

  <rule id="101000" level="6">
    <if_sid>92653</if_sid>
    <field name="win.eventdata.logonType">^10$</field>
    <description>RDP remote interactive logon: $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1021.001</id>
    </mitre>
  </rule>

  <rule id="101010" level="14" timeframe="300">
    <if_sid>101000</if_sid>
    <if_matched_sid>60204</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>RDP brute force succeeded: $(win.eventdata.targetUserName) logged in from $(win.eventdata.ipAddress) after repeated failed logons</description>
    <mitre>
      <id>T1110.001</id>
      <id>T1021.001</id>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,</group>
  </rule>

</group>
```

**Logic:** rule 101000 labels every RDP desktop logon (type 10). Rule 101010 fires only when a type-10 logon comes from the **same source IP** that triggered the multiple-failures alert (60204) in the previous 5 minutes, raising it to **level 14**.

**Result:** on re-test, rule 101010 fired at level 14 from 10.10.10.130, mapped to T1110.001, T1021.001 and T1078. Only 101010 shows, because the correlation rule consumes the 101000 alert into itself; its presence proves 101000 fired too.

**Lessons:**
- The guide's assumed rule ID for the RDP success (60106) was **wrong**; confirming it on the dashboard gave the real one, **92653**. Always verify IDs against live events before writing a rule.
- Rule field names use `win.eventdata.*`, not the dashboard's `data.win.eventdata.*` form.
- On this slow-HDD Wazuh VM, `systemctl start wazuh-manager` silently fails; `sudo /var/ossec/bin/wazuh-control start` reliably brings all daemons up (after removing a leftover `start-script-lock` if present).

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-11-rule-101010-fired.png"><img src="screenshots/Exercise-13/EX13-11-rule-101010-fired.png" width="400" alt="Rule 101010 fired at level 14"></a><br><sub>Rule 101010 fired at level 14</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-12-mitre-view.png"><img src="screenshots/Exercise-13/EX13-12-mitre-view.png" width="400" alt="MITRE mapping: T1110.001, T1021.001, T1078"></a><br><sub>MITRE mapping: T1110.001, T1021.001, T1078</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-05-nxc-rdp-bruteforce.png"><img src="screenshots/Exercise-13/EX13-05-nxc-rdp-bruteforce.png" width="400" alt="RDP brute force from Kali (nxc)"></a><br><sub>RDP brute force from Kali (nxc)</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-07-4625-failures.png"><img src="screenshots/Exercise-13/EX13-07-4625-failures.png" width="400" alt="Failed logons (4625) and brute-force correlation"></a><br><sub>Failed logons (4625) and brute-force correlation</sub></td>
  </tr>
</table>
<details>
<summary><b>More screenshots</b> (11)</summary>
<br>

<table>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-01-crash-watch.png"><img src="screenshots/Exercise-13/EX13-01-crash-watch.png" width="400" alt="Crash watch at lab start (clean after SSD move)"></a><br><sub>Crash watch at lab start (clean after SSD move)</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-02-rdp-enabled.png"><img src="screenshots/Exercise-13/EX13-02-rdp-enabled.png" width="400" alt="RDP enabled, port 3389 listening"></a><br><sub>RDP enabled, port 3389 listening</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-03-lockout-and-audit-policy.png"><img src="screenshots/Exercise-13/EX13-03-lockout-and-audit-policy.png" width="400" alt="Lockout threshold and logon audit policy"></a><br><sub>Lockout threshold and logon audit policy</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-04-nmap-3389-open.png"><img src="screenshots/Exercise-13/EX13-04-nmap-3389-open.png" width="400" alt="nmap: 3389 open (ms-wbt-server)"></a><br><sub>nmap: 3389 open (ms-wbt-server)</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-06-rdp-session-as-rdptest.png"><img src="screenshots/Exercise-13/EX13-06-rdp-session-as-rdptest.png" width="400" alt="RDP desktop session as rdptest (whoami)"></a><br><sub>RDP desktop session as rdptest (whoami)</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-07b-4625-json.png"><img src="screenshots/Exercise-13/EX13-07b-4625-json.png" width="400" alt="4625 detail: logon type 3, attacker IP"></a><br><sub>4625 detail: logon type 3, attacker IP</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-08-multiple-failures.png"><img src="screenshots/Exercise-13/EX13-08-multiple-failures.png" width="400" alt="Multiple failures correlation (rule 60204, T1110)"></a><br><sub>Multiple failures correlation (rule 60204, T1110)</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-09-4624-type10-success.png"><img src="screenshots/Exercise-13/EX13-09-4624-type10-success.png" width="400" alt="Successful RDP logon (4624 type 10, rule 92653)"></a><br><sub>Successful RDP logon (4624 type 10, rule 92653)</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-09b-4624-type10-success.png"><img src="screenshots/Exercise-13/EX13-09b-4624-type10-success.png" width="400" alt="4624 detail: logon type 10, attacker IP"></a><br><sub>4624 detail: logon type 10, attacker IP</sub></td>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-10-local-rules-101000-101010.png"><img src="screenshots/Exercise-13/EX13-10-local-rules-101000-101010.png" width="400" alt="Custom rules 101000 and 101010 in local_rules.xml"></a><br><sub>Custom rules 101000 and 101010 in local_rules.xml</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="50%"><a href="screenshots/Exercise-13/EX13-13-cleanup-rdp-off-user-deleted.png"><img src="screenshots/Exercise-13/EX13-13-cleanup-rdp-off-user-deleted.png" width="400" alt="Cleanup: rdptest deleted, RDP disabled, port closed"></a><br><sub>Cleanup: rdptest deleted, RDP disabled, port closed</sub></td>
    <td></td>
  </tr>
</table>

</details>

---

## 🎓 What I learned

- **Triage:** reading rule ID, level, source IP and MITRE mapping; deciding true vs false positive from the exact field values
- **Endpoint telemetry:** investigating process creation, registry and file events with Sysmon (image, command line, parent process)
- **Detection engineering:** finding detection gaps and closing them with custom Wazuh rules, including correlation rules and multi-condition rules that limit false positives
- **Knowing when NOT to write a rule:** distinguishing a rule gap (event arrives, no rule matches) from a visibility gap (event never reaches the SIEM), and documenting the gap instead of shipping a rule that can never fire
- **Rule internals:** Wazuh evaluates rules as a tree (`if_sid` vs `if_group`), the predecoder changes what `<match>` sees, and dashboard field names differ from rule field names
- **Tuning:** narrow level 0 suppression rules backed by negative tests, so tuning never creates blind spots
- **Attack coverage:** persistence (Run keys, scheduled tasks, Startup folder), lateral movement, tool transfer, SSH and RDP brute force, file tampering, and defense evasion (log clearing, disabling tools)
- **File integrity monitoring:** whodata answers who, what, when and how in a single alert; context (which folder, which file) decides whether a change is noise or an attack
- **Endpoint health as a detection problem:** losing visibility (agent down, host crashed) is itself an incident; an agent that is "Active" may still be sending nothing
- **Troubleshooting:** "no alerts" is not "no activity"; verify the log pipeline, read service logs, and fix a manager that will not start
- **Root-cause analysis:** testing the obvious suspect before acting on it, then using the event log timeline and a WinDbg crash dump to trace a `0x124` to a storage-driver timeout instead of guessing

The detailed version, with what happened and what I changed in each case, is in [docs/03-lessons-learned.md](docs/03-lessons-learned.md).

## 🚀 Next steps

- Tune a child of rule 506 to raise "Wazuh agent stopped" to high severity
- Close the crash/shutdown visibility gap with agent-side bookmark persistence or host/hypervisor-level monitoring
- Tune rule 92219 noise caused by Windows Update (`C:\Windows\SoftwareDistribution`)
- Enable auditd to capture sudo execution on Linux
- Add Wazuh Active Response to auto-block a brute-force source IP (the Windows quirk: the attacker IP is not in the `srcip` field)
- Next exercises: more detection scenarios, then a web penetration testing lab and a network security lab
