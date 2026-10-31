# SOC Home Lab: Detection Engineering with Wazuh

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh%204.x-blue)
![Sysmon](https://img.shields.io/badge/Telemetry-Sysmon-informational)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![Kali Linux](https://img.shields.io/badge/Attacker-Kali%20Linux-557C94)
![VMware](https://img.shields.io/badge/Lab-VMware%20Workstation-607078)

## Overview

A hands-on Security Operations Center (SOC) home lab built on VMware Workstation with a Wazuh SIEM, a Windows 11 endpoint running Sysmon, and a Kali Linux attacker. In each exercise I simulate a real attacker technique, investigate the resulting logs, close detection gaps with custom Wazuh rules mapped to MITRE ATT&CK, tune false positives, and document the evidence.

**At a glance**
- **10 exercises**, from brute-force detection to file integrity monitoring
- **9 custom detection rules** (levels 10 to 14) and **2 false-positive suppression rules**
- **MITRE ATT&CK coverage:** T1136.001, T1033, T1547.001, T1053.005, T1021, T1105, T1110.001, T1078, T1565.001
- **Skills:** Windows Event Log and Sysmon analysis, Linux auth log analysis, detection engineering, false-positive tuning, file integrity monitoring, attack timelines, log-pipeline troubleshooting

[TryHackMe progress](tryhackme-progress.md)

## Contents

- [Lab architecture](#lab-architecture)
- [Detection summary](#detection-summary)
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
- [What I learned](#what-i-learned)
- [Next steps](#next-steps)

## Lab architecture

| Role | Machine | IP / detail |
|---|---|---|
| Attacker | Kali Linux | 10.10.10.130 |
| Victim | Windows 11 Enterprise (agent: win11-victim) + Sysmon | 10.10.10.0/24 (DHCP) |
| SIEM | Wazuh on Ubuntu Server | 10.10.10.10 |

Isolated NAT network 10.10.10.0/24. Dashboard: `https://10.10.10.10`

**Tools:** VMware Workstation Pro, Wazuh 4.x (SIEM/XDR), Sysmon (SwiftOnSecurity config), Kali Linux (nmap, hydra, netexec), PowerShell, Git

## Detection summary

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
| Opened PowerShell several times | No 92213 alerts | 14 `__PSScriptPolicyTest` events reached the manager, **0 alerts** ✅ |
| Ran `sdbinst.exe -m -bg` from an admin PowerShell (negative test) | 92058 still alerts | **92058 fired at level 12** ✅ |

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

On 13 Oct, a full chain (discovery, then account creation, Run key and scheduled task persistence) was detected within about four minutes. Together with this exercise, six custom rules covered six MITRE techniques (see the [detection summary](#detection-summary)).

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

## What I learned

- **Triage:** reading rule ID, level, source IP and MITRE mapping; deciding true vs false positive from the exact field values
- **Endpoint telemetry:** investigating process creation, registry and file events with Sysmon (image, command line, parent process)
- **Detection engineering:** finding detection gaps and closing them with custom Wazuh rules, including correlation rules and multi-condition rules that limit false positives
- **Rule internals:** Wazuh evaluates rules as a tree (`if_sid` vs `if_group`), the predecoder changes what `<match>` sees, and dashboard field names differ from rule field names
- **Tuning:** narrow level 0 suppression rules backed by negative tests, so tuning never creates blind spots
- **Attack coverage:** persistence (Run keys, scheduled tasks, Startup folder), lateral movement, tool transfer, SSH brute force and file tampering
- **File integrity monitoring:** whodata answers who, what, when and how in a single alert; context (which folder, which file) decides whether a change is noise or an attack
- **Troubleshooting:** "no alerts" is not "no activity"; verify the log pipeline, read service logs, and fix a manager that will not start

## Next steps

- Custom rule for unexpected endpoint shutdowns and bugchecks (Event IDs 41, 6008, 1001 in the System log)
- Tune rule 92219 noise caused by Windows Update (`C:\Windows\SoftwareDistribution`)
- Enable auditd to capture sudo execution on Linux
- Next exercises: more detection scenarios, then a web penetration testing lab and a network security lab
