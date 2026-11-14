# Detection Rules

[← Back to README](../README.md)

Every custom rule in this lab was written to close a gap that I first proved with a real attack: the event reached the SIEM, but the built-in ruleset either missed it, alerted at a level that would be lost in a busy queue, or mapped it to the wrong MITRE technique. Each rule was then re-tested until it fired on live data.

The deployable rule file is [`rules/local_rules.xml`](../rules/local_rules.xml), an exact copy of the file running on the Wazuh manager.

## Custom detection rules

| Rule | Level | Detects | Parent / logic | Data source | MITRE ATT&CK | Exercise |
|---|---|---|---|---|---|---|
| 100100 | 12 | New local user created | Event 4720 | Windows Security | T1136.001 Create Account: Local Account | [4](../README.md#exercise-4-first-custom-detection-rule) |
| 100200 | 10 | `whoami.exe` executed | `if_group sysmon_event1` + image `whoami.exe` | Sysmon 1 | T1033 System Owner/User Discovery | [5](../README.md#exercise-5-sysmon-telemetry-and-recon-detection) |
| 100300 | 12 | Registry Run / RunOnce key modified (any process) | child of 92300 / 92302, `targetObject` `CurrentVersion\\+Run(Once)?\\+` (fixed in Exercise 17: was reg.exe only) | Sysmon 13 | T1547.001 Registry Run Keys / Startup Folder | [6](../README.md#exercise-6-persistence-detection), [17](../README.md#exercise-17-full-attack-chain-investigation-and-incident-report) |
| 100400 | 12 | Scheduled task created | `schtasks.exe` AND `/create` | Sysmon 1 | T1053.005 Scheduled Task | [6](../README.md#exercise-6-persistence-detection) |
| 100500 | 12 | Network logon (type 3), possible lateral movement | child of 92657, `logonType ^3$` | Windows Security 4624 | T1021 Remote Services | [8](../README.md#exercise-8-lateral-movement-tool-transfer-and-alert-tuning) |
| 100600 | 12 | PowerShell web download | child of 92027, PowerShell image + download cmdlets | Sysmon 1 | T1105 Ingress Tool Transfer | [8](../README.md#exercise-8-lateral-movement-tool-transfer-and-alert-tuning) |
| 100800 | 14 | SSH brute force that **succeeded** | child of 40112, `Accepted password` | Linux auth log | T1110.001 Password Guessing, T1078 Valid Accounts | [9](../README.md#exercise-9-linux-ssh-brute-force-and-successful-login) |
| 100900 | 10 | Sensitive Finance file modified or deleted | child of 550 / 553, path `C:\FIM-Test\Finance\` | FIM (whodata) | T1565.001 Stored Data Manipulation | [10](../README.md#exercise-10-file-integrity-monitoring-and-startup-persistence) |
| 100910 | 12 | File added to a Windows Startup folder | child of 554, path `\Start Menu\Programs\Startup\` | FIM (whodata) | T1547.001 Registry Run Keys / Startup Folder | [10](../README.md#exercise-10-file-integrity-monitoring-and-startup-persistence) |
| 100930 | 12 | Windows event log cleared | child of 63103 / 63104, Event 1102 or 104 | Windows Security / System | T1070.001 Clear Windows Event Logs | [11](../README.md#exercise-11-defense-evasion-and-endpoint-health) |
| 101000 | 6 | RDP remote interactive logon (type 10) | child of 92653, `logonType ^10$` | Windows Security 4624 | T1021.001 Remote Desktop Protocol | [13](../README.md#exercise-13-rdp-brute-force-and-successful-remote-logon) |
| 101010 | 14 | RDP brute force that **succeeded** | child of 101000, `if_matched_sid 60204`, same source IP, 300 s | Windows Security 4624 + 4625 | T1110.001, T1021.001, T1078 | [13](../README.md#exercise-13-rdp-brute-force-and-successful-remote-logon) |
| 101020 | 12 | RDP login after **any** failed logon from the same IP (below 60204's 8-failure threshold) | child of 101000, `if_matched_sid 60122`, same `ipAddress`, 300 s; group `rdp_bruteforce_success` | Windows Security 4624 + 4625 | T1110.001, T1021.001, T1078 | [17](../README.md#exercise-17-full-attack-chain-investigation-and-incident-report) |
| 101200 | 10 | Sudo run by a **non-admin** login user | child of 80792 (audit command), exe `/sudo$`, auid not `^1000$` | auditd execve | T1548.003 Sudo and Sudo Caching | [15](../README.md#exercise-15-linux-privilege-escalation-visibility-with-auditd) |
| 101210 | 12 | `/etc/shadow` read attempt (allowed or denied) | child of 80784, key `audit-wazuh-r`, exe not unix_chkpwd / sshd-session / systemd-executor / Wazuh / sudo | auditd file watch | T1003.008 /etc/passwd and /etc/shadow | [15](../README.md#exercise-15-linux-privilege-escalation-visibility-with-auditd) |
| 101220 | 12 | Sudoers file created, modified, chmod or deleted | child of 80780–80782, 80786–80788, 80790, 80791, key `audit-wazuh-w` | auditd file watch | T1548.003 Sudo and Sudo Caching | [15](../README.md#exercise-15-linux-privilege-escalation-visibility-with-auditd) |
| 101300 | 12 | Encoded PowerShell command (`-e`, `-ec`, `-enc`, `-EncodedCommand`), **any parent** | child of 61603, 92027, 92032, 92057; PowerShell image + encoded flag + 20+ base64 characters | Sysmon 1 | T1059.001 PowerShell, T1027.010 Command Obfuscation | [16](../README.md#exercise-16-powershell-attacks--script-block-logging-and-encoded-commands) |
| 101310 | 12 | Download cradle in a PowerShell script block | child of 91802, 91837; `DownloadString`, `Net.WebClient`, `Invoke-WebRequest`, `iwr`, `Start-BitsTransfer` | PowerShell 4104 | T1059.001, T1105 Ingress Tool Transfer | [16](../README.md#exercise-16-powershell-attacks--script-block-logging-and-encoded-commands) |
| 101315 | 8 | Full-spelling `Invoke-Expression` (built-in 91837 searches for the typo `Invoke-Expresion`) | child of 91802 | PowerShell 4104 | T1059.001 PowerShell | [16](../README.md#exercise-16-powershell-attacks--script-block-logging-and-encoded-commands) |
| 101320 | 10 | Run-time decoding or code rebuilding | child of 91802, 91809, 91837; `FromBase64String`, `[char[]]`, `-bxor`, string concatenation | PowerShell 4104 | T1027.010, T1140 Deobfuscate/Decode | [16](../README.md#exercise-16-powershell-attacks--script-block-logging-and-encoded-commands) |
| 101330 | 12 | Script Block Logging disabled or removed | child of 91802; `EnableScriptBlockLogging` set to 0 / `$false`, `reg ... /d 0`, or the key removed | PowerShell 4104 | T1562.002 Disable Windows Event Logging | [16](../README.md#exercise-16-powershell-attacks--script-block-logging-and-encoded-commands) |
| 101400 | **15** | **Incident:** persistence within 1 hour of a successful RDP password-guessing login | child of 100100, 100300, 100400, 91844; `if_matched_group rdp_bruteforce_success` (101010 or 101020), 3,600 s | Correlation | T1110.001, T1547.001, T1053.005, T1136.001 | [17](../README.md#exercise-17-full-attack-chain-investigation-and-incident-report) |
| 101550 | 12 | Wazuh agent stopped: the SOC is blind to that endpoint | child of 506 (level 3) | Wazuh agent / manager | T1562.001 Disable or Modify Tools | [11](../README.md#exercise-11-defense-evasion-and-endpoint-health), [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) |

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

Level 0 means "match, but do not alert". Every rule matches one exact benign pattern under its parent and needs a **positive test** (the noise stops) and a **negative test** (similar activity still alerts). Exercise 18 showed why both are needed: 100710 passed its negative test for ten exercises while never matching anything. Full method and proofs: [04-tuning.md](04-tuning.md).

| Rule | Suppresses | Matches only when | Negative test | Exercise |
|---|---|---|---|---|
| 100700 | 92213 "Executable file dropped in folder commonly used by malware" | image is `powershell.exe` / `pwsh.exe` **and** file is `__PSScriptPolicyTest_*.ps1` | 14 policy-test events, 0 alerts | [8](../README.md#83-tuning-false-positives) |
| 100710 | 92058 "Application Compatibility Database launched" | image is `System32\sdbinst.exe`, command line is exactly `-m -bg` **and** parent is `svchost.exe` (PcaSvc) | `sdbinst -m -bg` run from an admin shell still alerted at level 12. **Never matched until Exercise 18** (single `\\` in an anchored path; fixed to `\\+`), positive test pending | [8](../README.md#83-tuning-false-positives), [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) |
| 101500 | 92219 "Possible DLL search order hijack" (L6) | image `System32\svchost.exe` **and** file in `\Windows\SoftwareDistribution\Download\` or `\Windows\SystemTemp\` (Windows Update) | `C:\Windows\ex18-negtest.dll` from PowerShell still alerted (92203) | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) |
| 101510 | 92217 "Executable dropped in Windows root folder" (L6) | same image and folders (Defender definition patch) | other processes still alert (`mscorsvw.exe`, After v2) | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) |
| 101520 | 92213 (L15) | image `msedge.exe` **and** path `\msedge_chrome_Unpacker_BeginUnzipping<n>_<n>\` | not re-triggered yet | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) |
| 101530 | 91816 (PowerShell 4104) | the Wazuh agent's own SCA `secedit` line, anchored `^...$` | any other script text still reaches 91816 | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) |

## Severity corrections

| Rule | Parent (was) | New level | Matches only when | Tests | Exercise |
|---|---|---|---|---|---|
| 101540 | 61632 `smss.exe` (L12) | 3 | image `System32\smss.exe` **and** command `smss.exe <hex> <hex> winlogon.exe` (new logon session) | sign out / in → L3 | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) |
| 101560 | 100300 Run key (L12) | 3 | image exactly Edge's `msedge.exe` **and** value `MicrosoftEdgeAutoLaunch_<32 hex>` **and** data `--no-startup-window --win-session-start` | Edge → L3; **`reg add` Run key for notepad → 100300 L12** | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) |
| 101570 | 61618 `svchost.exe` (L12) | 3 | image exactly `System32\svchost.exe` **and** command exactly `-k osprivacy -p -s camsvc` | not re-triggered yet | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) |
| 101580 | 61634 `taskhost` (L12) | 3 | image exactly `System32\backgroundTaskHost.exe` **and** command ends `-ServerName:<app id>` | sign in → L3 | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) |
| 91823 | built-in, overwritten (L14) | 14 | `Invoke-Command` remote execution: `-Cn` / `-ComputerName` as a parameter only (`-(ComputerName\|Cn)\b`) | "acne" / "cnc" text: no alert; `-ComputerName localhost`: L14 | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) |

## MITRE ATT&CK coverage

| Tactic | Technique | Covered by |
|---|---|---|
| Initial Access / Persistence / Defense Evasion | T1078 Valid Accounts | 100800, 101010, 101020 |
| Persistence | T1136.001 Create Account: Local Account | 100100, 101400 |
| Persistence | T1547.001 Registry Run Keys / Startup Folder | 100300, 100910, 101400 |
| Persistence / Execution | T1053.005 Scheduled Task | 100400, 101400 |
| Credential Access | T1110.001 Password Guessing | 100800, 101010, 101020, 101400 |
| Discovery | T1033 System Owner/User Discovery | 100200 |
| Lateral Movement | T1021 Remote Services | 100500 |
| Lateral Movement | T1021.001 Remote Desktop Protocol | 101000, 101010, 101020 |
| Command and Control | T1105 Ingress Tool Transfer | 100600, 101310 |
| Defense Evasion | T1070.001 Clear Windows Event Logs | 100930 |
| Impact | T1565.001 Stored Data Manipulation | 100900 |
| Privilege Escalation | T1548.003 Sudo and Sudo Caching | 101200, 101220 |
| Credential Access | T1003.008 /etc/passwd and /etc/shadow | 101210 |
| Execution | T1059.001 PowerShell | 101300, 101310, 101315 |
| Defense Evasion | T1027.010 Command Obfuscation | 101300, 101320 |
| Defense Evasion | T1140 Deobfuscate/Decode Files or Information | 101320 |
| Defense Evasion | T1562.002 Disable Windows Event Logging | 101330 |
| Defense Evasion | T1562.001 Disable or Modify Tools | 101550 |

## Built-in coverage verified (no custom rule needed)

Not every test ended in a new rule. Where the built-in rule was already adequate, I recorded that instead.

| Activity | Built-in rule | Level | Verdict |
|---|---|---|---|
| Windows failed logons (4625) | 60122 | 5 | Adequate as a low-level signal; correlated by 60204 and (since Exercise 17) 101020 |
| Multiple failed Windows logons | 60204 | 10 | Needs `MS_FREQ` = 8 failures in 240 s from one IP: blind to a short guess list (Exercise 17), so 101020 now covers the gap |
| User added to Administrators (4732) | 60154 | 12 | Adequate |
| SSH brute force (Linux) | 5763 / 2502 | 10 | Adequate |
| Wazuh agent stopped | 506 | 3 | Correct MITRE (T1562.001) but severity too low: raised to level 12 by 101550 (Exercise 18) |
| Successful SSH login | 5715 | 3 | Adequate as a signal; correlated by 40112 / 100800 |
| `FromBase64String` in a PowerShell script block | 91809 | 10 | Adequate; 101320 adds `[char[]]`, `-bxor` and string concatenation |
| `-EncodedCommand` / `-e` with a PowerShell parent | 92057 | 12 | Adequate for those cases only; see built-in rule defects below |

## Documented gaps (no rule possible yet)

| Gap | Why a rule would not help | Possible fix |
|---|---|---|
| Endpoint crash / unexpected shutdown (Events 41, 6008) | Events are written while the agent is down and are never forwarded | Host or hypervisor-level monitoring |
| Events written while the Wazuh agent is stopped | The agent does not replay missed EventChannel events | Treat agent stop as a high-severity incident |
| Stopping Sysmon | Not possible: Sysmon64 is self-protected (denied even as SYSTEM) | Positive finding, no rule needed |
| Windows auto-block on logon alerts | Stock response scripts read only `srcip`, which Windows EventChannel alerts do not fill | Custom response script reading `win.eventdata.ipAddress`, or block at the network edge |
| PowerShell 7 (`pwsh.exe`) script blocks | They are written to `PowerShell Core/Operational`, which the agent does not collect | Add a second `<localfile>` for that channel |
| Registry change that disables Script Block Logging | The Sysmon config does not watch the key (no Event 13); 101330 relies on the disabling command appearing in 4104 | Add the key to the Sysmon config |
| Port scans | No network sensor in the lab; Windows logs nothing for a SYN scan (Exercise 17) | Network IDS (e.g. Suricata) or firewall logs |
| Discovery commands (`net user`, `net localgroup`, `ipconfig`, `systeminfo`) | Only `whoami` (100200) alerts; the others are common admin commands (Exercise 17) | Discovery-burst correlation rule |
| First SSH login of a newly created user sometimes not alerted (missed in Exercises 14 and 15, alerted in Exercise 18) | A new user's first login makes journald open a per-user journal; logcollector reports a "rotation" 1–2 s later and the events around it are sometimes skipped: a timing race | auditd records the login independently (`USER_LOGIN`). Production: read auth logs from one source only (journald filtered by unit, or auth.log), never both |

## Closed gaps

| Gap | Found in | Closed in | How |
|---|---|---|---|
| Denied `sudo` by a non-sudoer not logged (Ubuntu 26.04, sudo-rs) | [9](../README.md#exercise-9-linux-ssh-brute-force-and-successful-login) | [15](../README.md#exercise-15-linux-privilege-escalation-visibility-with-auditd) | auditd records the sudo execve and the `/etc/shadow` open at kernel level; rules 101200 (L10) and 101210 (L12) |
| Encoded PowerShell visible only as base64; `-enc` scored level 4 and a `cmd.exe` launch level 3 | [16](../README.md#exercise-16-powershell-attacks--script-block-logging-and-encoded-commands) | [16](../README.md#exercise-16-powershell-attacks--script-block-logging-and-encoded-commands) | Script Block Logging (4104) shows the decoded code; 101300 covers every spelling and parent (L12) |
| No detection for download cradles, `[char[]]` / string obfuscation or full `Invoke-Expression` | [16](../README.md#exercise-16-powershell-attacks--script-block-logging-and-encoded-commands) | [16](../README.md#exercise-16-powershell-attacks--script-block-logging-and-encoded-commands) | Rules 101310, 101315, 101320 on the decoded script block |
| RDP password guessing below 8 failures raised only level 5–6 alerts; 101010 never fired | [17](../README.md#exercise-17-full-attack-chain-investigation-and-incident-report) | [17](../README.md#exercise-17-full-attack-chain-investigation-and-incident-report) | 101020 (L12): RDP login after any failure from the same IP; 101400 (L15) correlates it with persistence |
| Wazuh agent stop raised only level 3 | [11](../README.md#exercise-11-defense-evasion-and-endpoint-health) | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) | 101550 (L12, T1562.001) |
| Endpoint Security log kept ~10 minutes (20 MB) | [17](../README.md#exercise-17-full-attack-chain-investigation-and-incident-report) | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) | Raised to 200 MB; the SIEM stays the durable copy |
| Endpoint clock ~37 s ahead (local CMOS clock, no NTP) | [17](../README.md#exercise-17-full-attack-chain-investigation-and-incident-report) | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) | Windows Time synced to `time.windows.com` |
| Every command by a login user logged by auditd (4,341 alerts in 35 min) | [15](../README.md#exercise-15-linux-privilege-escalation-visibility-with-auditd) | [18](../README.md#exercise-18-alert-tuning--less-noise-without-blind-spots) | Audit scope cut to `sudo`, `su`, `bash`, `curl`, `wget`, `nc`, `python3` |
| Run key created by PowerShell not detected by 100300 (reg.exe only) | [17](../README.md#exercise-17-full-attack-chain-investigation-and-incident-report) | [17](../README.md#exercise-17-full-attack-chain-investigation-and-incident-report) | 100300 moved to parent 92300 (any process), `Run\` / `RunOnce\` only |

## Built-in rule defects found

Found by testing attack variants and then reading the vendor rule files (Exercises 16 and 17).

| Rule | Defect | Effect | Handled by |
|---|---|---|---|
| 92057 | Spelling list `encodedcommand\|e\|ea\|ec\|encodeda\|encode\|en\|enco` has no `enc`; parent must be `powershell.exe` | `-enc` and any non-PowerShell parent are missed | 101300 |
| 91837 | Regex and description say `Invoke-Expresion` (typo) | Full `Invoke-Expression` never matches | 101315 |
| 91823 (L14) | `(?i)(ComputerName\|Cn)` with no word boundary | Level 14 false positive on a built-in Windows script and on any text containing "cn" | Overwritten with `-(ComputerName\|Cn)\b` (Exercise 18) |
| 92302 | Matches only `image` = `reg.exe` | A custom child (100300) missed a Run key set by PowerShell | 100300 now also a child of 92300 (Exercise 17) |
| 92213 (L15) | Fires on `msedge.exe` unpacking `well_known_domains.dll` into a new profile's Temp folder | Level 15 false positive at every first logon of a user | 101520 (Exercise 18) |
| 61632 / 61618 / 61634 (L12) | "Suspicious process" rules for `smss.exe`, `svchost.exe` and `taskhost` match by process name; normal logon instances that miss the built-in allow-list fire at level 12 | 7 of 8 level 12 alerts in an idle hour were a normal logon | 101540, 101570, 101580 lower the exact benign instances to level 3 (Exercise 18) |

## Rule-writing conventions

- Custom detections use IDs **100100 to 101999**; every rule has a MITRE mapping and a description with the key field values (`$(file)`, `$(win.eventdata.ipAddress)`, ...).
- A rule that raises a built-in alert is written as a **child** (`if_sid`), because Wazuh evaluates rules as a tree: once an event matches a parent, only that parent's children are checked.
- Rule IDs and field names are confirmed on live events first. Rule XML uses `win.eventdata.*` and `file`, not the dashboard names `data.win.eventdata.*` and `syscheck.path`.
- Correlation rules that must accept several triggers tag them with a shared group (`rdp_bruteforce_success`) and use `if_matched_group` (Exercise 17).
- When a built-in sibling rule can match the same event first, the custom rule lists that rule in `if_sid` too, so it is still evaluated (Exercise 16).
- Windows paths are matched with `\\+`, because Wazuh stores them with doubled backslashes; a single `\\` in an anchored regex never matches (100710, Exercise 18).
- Tuning never disables a rule ID: it adds a narrow child rule with a positive **and** a negative test ([04-tuning.md](04-tuning.md)).
- Every change is validated with `wazuh-analysisd -t` before the manager is restarted, and every rule is proven by a screenshot of it firing.
