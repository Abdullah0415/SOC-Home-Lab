# Detection Rules

[← Back to README](../README.md)

Every custom rule in this lab was written to close a gap that I first proved with a real attack: the event reached the SIEM, but the built-in ruleset either missed it, alerted at a level that would be lost in a busy queue, or mapped it to the wrong MITRE technique. Each rule was then re-tested until it fired on live data.

The deployable rule file is [`rules/local_rules.xml`](../rules/local_rules.xml), an exact copy of the file running on the Wazuh manager.

## Custom detection rules

| Rule | Level | Detects | Parent / logic | Data source | MITRE ATT&CK | Exercise |
|---|---|---|---|---|---|---|
| 100100 | 12 | New local user created | Event 4720 | Windows Security | T1136.001 Create Account: Local Account | [4](../README.md#exercise-4-first-custom-detection-rule) |
| 100200 | 10 | `whoami.exe` executed | `if_group sysmon_event1` + image `whoami.exe` | Sysmon 1 | T1033 System Owner/User Discovery | [5](../README.md#exercise-5-sysmon-telemetry-and-recon-detection) |
| 100300 | 12 | Registry Run key modified | Sysmon 13 on `CurrentVersion\Run` | Sysmon 13 | T1547.001 Registry Run Keys / Startup Folder | [6](../README.md#exercise-6-persistence-detection) |
| 100400 | 12 | Scheduled task created | `schtasks.exe` AND `/create` | Sysmon 1 | T1053.005 Scheduled Task | [6](../README.md#exercise-6-persistence-detection) |
| 100500 | 12 | Network logon (type 3), possible lateral movement | child of 92657, `logonType ^3$` | Windows Security 4624 | T1021 Remote Services | [8](../README.md#exercise-8-lateral-movement-tool-transfer-and-alert-tuning) |
| 100600 | 12 | PowerShell web download | child of 92027, PowerShell image + download cmdlets | Sysmon 1 | T1105 Ingress Tool Transfer | [8](../README.md#exercise-8-lateral-movement-tool-transfer-and-alert-tuning) |
| 100800 | 14 | SSH brute force that **succeeded** | child of 40112, `Accepted password` | Linux auth log | T1110.001 Password Guessing, T1078 Valid Accounts | [9](../README.md#exercise-9-linux-ssh-brute-force-and-successful-login) |
| 100900 | 10 | Sensitive Finance file modified or deleted | child of 550 / 553, path `C:\FIM-Test\Finance\` | FIM (whodata) | T1565.001 Stored Data Manipulation | [10](../README.md#exercise-10-file-integrity-monitoring-and-startup-persistence) |
| 100910 | 12 | File added to a Windows Startup folder | child of 554, path `\Start Menu\Programs\Startup\` | FIM (whodata) | T1547.001 Registry Run Keys / Startup Folder | [10](../README.md#exercise-10-file-integrity-monitoring-and-startup-persistence) |
| 100930 | 12 | Windows event log cleared | child of 63103 / 63104, Event 1102 or 104 | Windows Security / System | T1070.001 Clear Windows Event Logs | [11](../README.md#exercise-11-defense-evasion-and-endpoint-health) |
| 101000 | 6 | RDP remote interactive logon (type 10) | child of 92653, `logonType ^10$` | Windows Security 4624 | T1021.001 Remote Desktop Protocol | [13](../README.md#exercise-13-rdp-brute-force-and-successful-remote-logon) |
| 101010 | 14 | RDP brute force that **succeeded** | child of 101000, `if_matched_sid 60204`, same source IP, 300 s | Windows Security 4624 + 4625 | T1110.001, T1021.001, T1078 | [13](../README.md#exercise-13-rdp-brute-force-and-successful-remote-logon) |
| 101200 | 10 | Sudo run by a **non-admin** login user | child of 80792 (audit command), exe `/sudo$`, auid not `^1000$` | auditd execve | T1548.003 Sudo and Sudo Caching | [15](../README.md#exercise-15-linux-privilege-escalation-visibility-with-auditd) |
| 101210 | 12 | `/etc/shadow` read attempt (allowed or denied) | child of 80784, key `audit-wazuh-r`, exe not unix_chkpwd / sshd-session / systemd-executor / Wazuh / sudo | auditd file watch | T1003.008 /etc/passwd and /etc/shadow | [15](../README.md#exercise-15-linux-privilege-escalation-visibility-with-auditd) |
| 101220 | 12 | Sudoers file created, modified, chmod or deleted | child of 80780–80782, 80786–80788, 80790, 80791, key `audit-wazuh-w` | auditd file watch | T1548.003 Sudo and Sudo Caching | [15](../README.md#exercise-15-linux-privilege-escalation-visibility-with-auditd) |

## Response visibility rule

| Rule | Level | Detects | Parent / logic | Data source | MITRE ATT&CK | Exercise |
|---|---|---|---|---|---|---|
| 101100 | 8 | Attacker IP auto-blocked by Active Response, with a reminder to check for a login before the block | child of 651 (firewall-drop `add`) | Active Response log | n/a (our response, not attacker behaviour) | [14](../README.md#exercise-14-automated-response-with-wazuh-active-response) |

## Automated response

Configuration: [`config/active-response.xml`](../config/active-response.xml). Both responses are disabled after testing.

| Trigger | Response | Result |
|---|---|---|
| 5763 SSH brute force (L10) | `firewall-drop` (iptables), 180 s | Blocked ~2 s after detection, unblocked after 180 s, **but the attacker had already logged in** |
| 101010 RDP brute force succeeded (L14) | `netsh` (Windows Firewall), 180 s | **Failed**: `Cannot read 'srcip' from data`; the IP is in `win.eventdata.ipAddress` |

## False-positive suppression rules

Level 0 means "match, but do not alert". Both rules are deliberately narrow and were validated with a **negative test** to prove they do not create a blind spot.

| Rule | Suppresses | Matches only when | Negative test | Exercise |
|---|---|---|---|---|
| 100700 | 92213 "Executable file dropped in folder commonly used by malware" | image is `powershell.exe` / `pwsh.exe` **and** file is `__PSScriptPolicyTest_*.ps1` | 14 policy-test events, 0 alerts | [8](../README.md#83-tuning-false-positives) |
| 100710 | 92058 "Application Compatibility Database launched" | image is `System32\sdbinst.exe`, command line is exactly `-m -bg` **and** parent is `svchost.exe` (PcaSvc) | `sdbinst -m -bg` run from an admin shell still alerted at level 12 | [8](../README.md#83-tuning-false-positives) |

## MITRE ATT&CK coverage

| Tactic | Technique | Covered by |
|---|---|---|
| Initial Access / Persistence / Defense Evasion | T1078 Valid Accounts | 100800, 101010 |
| Persistence | T1136.001 Create Account: Local Account | 100100 |
| Persistence | T1547.001 Registry Run Keys / Startup Folder | 100300, 100910 |
| Persistence / Execution | T1053.005 Scheduled Task | 100400 |
| Credential Access | T1110.001 Password Guessing | 100800, 101010 |
| Discovery | T1033 System Owner/User Discovery | 100200 |
| Lateral Movement | T1021 Remote Services | 100500 |
| Lateral Movement | T1021.001 Remote Desktop Protocol | 101000, 101010 |
| Command and Control | T1105 Ingress Tool Transfer | 100600 |
| Defense Evasion | T1070.001 Clear Windows Event Logs | 100930 |
| Impact | T1565.001 Stored Data Manipulation | 100900 |
| Privilege Escalation | T1548.003 Sudo and Sudo Caching | 101200, 101220 |
| Credential Access | T1003.008 /etc/passwd and /etc/shadow | 101210 |

## Built-in coverage verified (no custom rule needed)

Not every test ended in a new rule. Where the built-in rule was already adequate, I recorded that instead.

| Activity | Built-in rule | Level | Verdict |
|---|---|---|---|
| Windows failed logons (4625) | 60122 | 5 | Adequate as a low-level signal; correlated by 60204 |
| Multiple failed Windows logons | 60204 | 10 | Adequate; used as the trigger for 101010 |
| User added to Administrators (4732) | 60154 | 12 | Adequate |
| SSH brute force (Linux) | 5763 / 2502 | 10 | Adequate |
| Wazuh agent stopped | 506 | 3 | Correct MITRE (T1562.001) but severity too low, tuning planned |
| Successful SSH login | 5715 | 3 | Adequate as a signal; correlated by 40112 / 100800 |

## Documented gaps (no rule possible yet)

| Gap | Why a rule would not help | Possible fix |
|---|---|---|
| Endpoint crash / unexpected shutdown (Events 41, 6008) | Events are written while the agent is down and are never forwarded | Host or hypervisor-level monitoring |
| Events written while the Wazuh agent is stopped | The agent does not replay missed EventChannel events | Treat agent stop as a high-severity incident |
| Stopping Sysmon | Not possible: Sysmon64 is self-protected (denied even as SYSTEM) | Positive finding, no rule needed |
| Windows auto-block on logon alerts | Stock response scripts read only `srcip`, which Windows EventChannel alerts do not fill | Custom response script reading `win.eventdata.ipAddress`, or block at the network edge |
| First SSH login of a newly created user not alerted (seen twice: Exercises 14 and 15) | The `Accepted password` line is in journald, but logcollector logs "Journald timestamp was refreshed due to rotation" within one second and skips it; later logins alert normally | Test the per-user journal file hypothesis in Exercise 18; until then, check the source log after any auto-block or new account |

## Closed gaps

| Gap | Found in | Closed in | How |
|---|---|---|---|
| Denied `sudo` by a non-sudoer not logged (Ubuntu 26.04, sudo-rs) | [9](../README.md#exercise-9-linux-ssh-brute-force-and-successful-login) | [15](../README.md#exercise-15-linux-privilege-escalation-visibility-with-auditd) | auditd records the sudo execve and the `/etc/shadow` open at kernel level; rules 101200 (L10) and 101210 (L12) |

## Rule-writing conventions

- Custom detections use IDs **100100 to 101999**; every rule has a MITRE mapping and a description with the key field values (`$(file)`, `$(win.eventdata.ipAddress)`, ...).
- A rule that raises a built-in alert is written as a **child** (`if_sid`), because Wazuh evaluates rules as a tree: once an event matches a parent, only that parent's children are checked.
- Rule IDs and field names are confirmed on live events first. Rule XML uses `win.eventdata.*` and `file`, not the dashboard names `data.win.eventdata.*` and `syscheck.path`.
- Every change is validated with `wazuh-analysisd -t` before the manager is restarted, and every rule is proven by a screenshot of it firing.
