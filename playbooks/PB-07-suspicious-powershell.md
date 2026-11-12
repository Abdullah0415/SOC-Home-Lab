# PB-07: Suspicious PowerShell

**Triggers:** 101300 (encoded command, L12), 101310 (download cradle, L12), 101320 (decoding / obfuscation, L10), 101315 (Invoke-Expression, L8), 101330 (Script Block Logging disabled, L12); built-in 92057, 91809, 91837
**MITRE:** T1059.001 PowerShell · T1027.010 Command Obfuscation · T1105 Ingress Tool Transfer · T1140 Deobfuscate/Decode · T1562.002 Disable Windows Event Logging
**Data source:** Sysmon Event 1 (process creation) and PowerShell Event 4104 (decoded script blocks)
**Related:** PB-04 (tool transfer), PB-02 (persistence), PB-03 (log cleared), PB-05 (telemetry loss), Exercise 8, Exercise 16

## 1. Triage (first 5 minutes)
1. Note the host, the time (dashboard = local time, server logs = UTC), the user and the rule.
2. **101300 (Sysmon 1):** read `data.win.eventdata.user`, `parentImage` and `commandLine`. A parent of `cmd.exe`, `wscript.exe`, `mshta.exe`, an Office application or a browser is far more suspicious than an admin's PowerShell window.
3. **Find the decoded code.** Search the same host around the same time:
   `agent.name:<host> and data.win.system.eventID:4104`
   The script block shows what the base64 really did. If needed, decode the command line yourself (UTF-16LE base64) on an analysis machine, never by running it.
4. **101310:** take the URL or IP from `scriptBlockText`. Is it internal, a known update server, or unknown?
5. **101330:** treat it as an attacker preparing to hide. Everything after this time on the host may be missing from 4104.

| Situation | Severity |
|---|---|
| Encoded command or cradle from an admin's known script, signed, on schedule | Likely benign: confirm with the owner, then tune |
| Encoded command with an unusual parent (Office, browser, `cmd.exe` from a document) | **High** |
| Download cradle to an unknown or external host, executed in memory (`IEX`, `Invoke-Expression`) | **Critical** |
| 101330 (logging turned off) by anyone without a change ticket | **Critical** |

## 2. Investigate
1. **Process tree:** from the Sysmon 1 alert, follow `parentProcessGuid` / `processGuid` to see what started PowerShell and what PowerShell started (`whoami`, `net`, `reg`, `schtasks`, ...).
2. **Network:** Sysmon Event 3 from `powershell.exe` to the cradle's host and port:
   `agent.name:<host> and data.win.system.eventID:3 and data.win.eventdata.image:*powershell.exe`
3. **Long scripts:** big scripts arrive as several 4104 events (`messageNumber` 1 of N). Read all parts by `scriptBlockId`.
4. **Follow-on activity:** look for persistence (PB-02), new users (100100), lateral movement (PB-04) and log clearing (PB-03) on the same host after the alert.
5. **For 101330:** check whether 4104 events from this host stop after the alert; if they do, the change took effect for new PowerShell processes (PB-05).

## 3. Contain
- Isolate the host or block the download host / IP at the firewall.
- Kill the PowerShell process (`Stop-Process -Id <pid>`) after saving evidence.
- Disable or reset the user account if the activity was not theirs.
- For 101330: set `EnableScriptBlockLogging` back to 1 and confirm 4104 events arrive again.

## 4. Eradicate and recover
- Remove downloaded files and any persistence found in step 2.
- Reset credentials used on the host if the script touched credentials or ran as an admin.
- Confirm Sysmon, the Wazuh agent and Script Block Logging are all running.

## 5. Lessons / tuning
- Legitimate admin scripts also use `Invoke-WebRequest` and `Invoke-Expression`. Exclude them by script path, signer or host, with evidence from the alert JSON, never by removing the keyword.
- Known 4104 noise in this lab: the Wazuh agent's SCA scan (`secedit /export`, rule 91816), Windows maintenance scripts (91820) and the 91823 false positive.
