# Lessons Learned

[← Back to README](../README.md)

The practical lessons from the lab, grouped by theme. Each one came from something that broke, misled me, or surprised me during an exercise, and each one changed how I work.

## Detection engineering

| Lesson | What happened | What I do now | Exercise |
|---|---|---|---|
| Wazuh evaluates rules as a tree | Rule 100600 used `if_group sysmon_event1` and never fired, because the event had already matched built-in rule 92027 and only its children were checked | Raise built-in alerts with a child rule (`if_sid`) | 8 |
| The predecoder changes what `<match>` sees | Rule 100800 with `<match>sshd</match>` never fired: the program name is moved into its own field | Match on the message text (`Accepted password`) | 9 |
| Dashboard field names are not rule field names | The dashboard shows `syscheck.path` and `data.win.eventdata.*`; rules need `file` and `win.eventdata.*` | Check the rule-side field name before writing the rule | 10, 13 |
| Never trust an assumed rule ID | The planned parent for RDP success (60106) was wrong; the live event showed 92653 | Confirm every parent ID on a real event first | 13 |
| A correlation rule consumes its child | Only 101010 appeared, not 101000, after the re-test | The correlation alert is the proof the child fired | 13 |
| Escaping in JSON fields | The Run key path is backslash-escaped, so the regex needed `CurrentVersion\\+Run` | Test regexes against the raw JSON event | 6 |
| Context decides severity | The same FIM rule (level 7) fired for a routine file and for a sensitive Finance file | Raise severity by path, not by event type alone | 10 |
| A built-in rule existing is not coverage | 92057 missed `-enc` and any non-PowerShell parent; 91837 has a typo (`Invoke-Expresion`) | Test every variant, then read the vendor rule to explain each miss | 16 |
| Sibling rules compete | Two children of the same parent can match one event, but only one is reported | List the competing built-in rule in `if_sid` as well; the higher-level custom rule won in the re-test | 16 |
| A threshold is a blind spot | 60204 needs 8 failures in 240 s; a 4-guess attack stayed at level 5–6 and broke the 101010 chain | Correlate "failure followed by success" (101020) instead of only counting failures | 17 |
| Test a rule with more than one tool | 100300 was written for `reg.exe`; a PowerShell Run key was logged by Sysmon but raised no custom alert | Recreate each technique with a second tool before trusting the rule | 17 |
| Rules may match the channel, not the Event ID | Searching the ruleset for "4104" found nothing; the PowerShell parents are 91801 → 91802 (level 0) | Find the parent from a live alert's rule ID, then read its file | 16 |

## Tuning

| Lesson | What happened | What I do now | Exercise |
|---|---|---|---|
| Suppress the pattern, not the rule | Not every 92213 alert was the PowerShell policy-test file | Level 0 child rules matching the exact process **and** file / command line / parent | 8 |
| A suppression needs a negative test | Proved `sdbinst -m -bg` from an admin shell still alerts after rule 100710 | Every suppression ships with a test showing real activity still alerts | 8 |
| Your own tools make noise | 8 of the first 4104 alerts were the Wazuh agent's SCA scan (`secedit /export`) | Identify the source of every new alert before tuning | 16 |
| Severity is not priority | The only level 15 alerts in the intrusion were Edge unpacking a DLL; the attacker's entry was level 5–6 | Verify every high alert and look below level 10 around the first sign of an attack | 17 |
| Group alerts before reading them | 105 alerts in 20 minutes, 68% noise; grouped by rule they became 24 lines | Summarise by rule (first, last, count) before reading one by one | 17 |
| Measure before trusting the count | 243 script blocks → 22 alerts, 12 of them noise from three known sources | Count by rule and script text after enabling any new log source | 16 |
| A suppression needs a positive test too | 100710 passed its negative test in Exercise 8 but never matched: one `\\` in an anchored path, while Wazuh stores two | Prove the noise stops **and** the attack still fires; match paths with `\\+` | 18 |
| Lower severity before silencing | 7 of 8 level 12 alerts in an idle hour were normal logon processes | Level 3 child rules keep the record searchable without training analysts to ignore level 12 | 18 |
| Some alerts are never tuned | 92206: `spoolsv.exe` wrote a DLL into the printer driver folder; it was Microsoft-signed | Triage rare, high-value alerts (signature check) every time; PrintNightmare uses the same path | 18 |
| Alert count is a weak metric | After tuning, the idle-hour total rose (58 → 107 → 69) because Windows did different work each hour | Compare the targeted rules and what level 10+ means, not only the total | 18 |
| Do not touch the system while measuring | One `sudo` check during a measurement window added ~6 alerts | No input on any VM during a window | 18 |

## Log pipeline and visibility

| Lesson | What happened | What I do now | Exercise |
|---|---|---|---|
| "No alerts" is not "no activity" | A negative test seemed to pass, but the agent had stopped sending Windows logs | Check that events are arriving (archives) before trusting a result | 8 |
| "Active" is not "sending" | After a crash the agent showed Active but sent only SCA and rootcheck data | Verify real EventChannel events, restart the agent if needed | 11 |
| Agent down = permanent blind spot | An event written while the agent was stopped was never recovered after restart | Treat an agent stop as a high-severity incident | 11 |
| Rule gap vs visibility gap | Crash events (41, 6008) never reached the manager at all | Do not ship rules for data that never arrives; document the gap instead | 11 |
| Same Event ID, different meaning | Event 1001 exists in System (bugcheck) and Application (Windows Error Reporting) | Filter by channel and provider, not just Event ID | 10 |
| Some systems do not log what you expect | sudo-rs on Ubuntu 26.04 did not log denied `sudo` attempts | Verify the log exists before planning a detection; auditd as a fix | 9 |
| Local logs are not durable evidence | The cleared 20 MB Security log refilled in ~18 minutes and overwrote its own Event 1102 | Treat the SIEM copy as the evidence; size endpoint logs for days, not minutes | 17 |
| Clocks drift | The endpoint was ~37 s ahead of the manager and Kali | Build timelines on one clock (the manager) and note the skew | 17 |
| Command lines hide encoded code | Sysmon showed only `-EncodedCommand VwBy...` | Collect PowerShell 4104, which records the decoded script block | 16 |
| Policy changes apply to new processes | After setting Script Block Logging to 0, the running session kept logging and recorded the change | Test logging changes in a new window; a running session is evidence | 16 |

## Operating the SIEM

| Lesson | What happened | What I do now | Exercise |
|---|---|---|---|
| Slow storage breaks service restarts | `systemctl restart wazuh-manager` timed out and left daemons stopped | `wazuh-control stop`, remove `start-script-lock` (a directory: `rm -rf`), `wazuh-control start` | 5, 10, 11, 13 |
| Glob patterns run as the user, not root | `sudo grep ... /var/ossec/ruleset/rules/*.xml` failed: the shell expands `*` before sudo | Use `sudo grep -r` on the folder | 14 |
| Windows profiles need a proper removal | `Remove-Item C:\Users\<user>` left the profile behind | `Get-CimInstance Win32_UserProfile ... \| Remove-CimInstance` | 14 |
| Unneeded modules cost stability | Vulnerability detection feed errors crashed `wazuh-modulesd` and the dashboard API | Disable what the lab does not need | 8 |
| Keep a second way in | During API outages I verified alerts over SSH with `alerts.json` / `archives.json` | Always know how to read alerts without the dashboard | 8 |
| DQL type quirks | `agent.id:000` returns nothing (parsed as a number) | Use `agent.name:soc-wazuh` | 9 |
| Timezones | Server logs are UTC, the dashboard is UTC+2 | Every timeline states its timezone | 9 |
| Elevated editors on Windows 11 | The tabbed Notepad opened `ossec.conf` in an existing non-admin window ("no permission") | Start Notepad as administrator, then File → Open | 16 |
| Test servers change the data type | Python's `http.server` serves `.ps1` as binary, so `Invoke-WebRequest` returned bytes | Decode with `[Text.Encoding]::UTF8.GetString(...)` | 16 |

## Automated response

| Lesson | What happened | What I do now | Exercise |
|---|---|---|---|
| Containment is not prevention | The SSH block landed ~2 s after detection, but the attacker had logged in 1 s earlier (reproduced twice) | After any auto-block, check the source log for a successful login and reset the password | 14 |
| A response depends on fields, not just rules | Rule 101010 fired at level 14, but netsh logged "Cannot read 'srcip'" and nothing was blocked | Check which fields a response script needs before relying on it | 14 |
| Responses must be visible | The built-in "Host Blocked" alert (651) is only level 3 | Rule 101100 raises it to level 8 with a next-step hint | 14 |
| Absence of an alert is not proof | One brute-forced login was in journald but never alerted (likely a journald rotation at that second) | Compare the SIEM with the source log when the stakes are high | 14 |
| Test responses safely | A wrong block could lock the analyst out | Whitelist the analyst IP, short timeout, disable the response after testing | 14 |

## Troubleshooting method

| Lesson | What happened | What I do now | Exercise |
|---|---|---|---|
| Test the obvious suspect before acting on it | 55 minutes of CPU stress at the thermal limit did not reproduce the `0x124` crash | Reproduce a hypothesis before "fixing" it | 12 |
| Read the evidence, not the label | The `GenuineIntel.sys` failure bucket pointed at the CPU; the stack showed a storage-driver reset | Use the crash dump stack and Event 129 history to find the real actor | 12 |
| Change one variable at a time | Moved only the endpoint VM to the SSD, changed nothing else | One change, one validation test, one crash-log entry | 12 |

## Positive findings

- **Sysmon is hard to kill.** `Stop-Service`, `sc.exe stop`, `Stop-Process -Force` and PsExec as SYSTEM were all denied (Exercise 11). Endpoint telemetry cannot be trivially disabled by an attacker with admin rights.
- **FIM and Sysmon complement each other.** A file created outside the monitored folders was missed by FIM but caught by Sysmon (Exercise 10).
- **Whodata answers who, what and how in one alert:** user, process, PID and the exact line changed (Exercise 10).

## Exercise 15: Linux privilege escalation with auditd
- **Silent tools can still be watched.** sudo-rs does not log denied sudo, but the kernel still sees the execve and the /etc/shadow open. auditd turns "the tool did not log it" into "the kernel recorded it".
- **auid is "who logged in", not "which program".** The attacker's sudo and the admin's sudo were identical apart from auid. Services started with `sudo` (e.g. Wazuh's daemons after `sudo wazuh-control start`) inherit the admin's auid.
- **Built-in descriptions can mislead.** Wazuh rule 80784 says "Read access" even when the read was denied. The `success` field holds the truth, so the custom rule puts it in the description.
- **Find legitimate readers before writing an alert.** /etc/shadow is read by unix_chkpwd (each sudo), sshd-session and systemd-executor (each login) and Wazuh itself. Without excluding them, 101210 would fire at level 12 on every login.
- **Ubuntu 26.04 uses Rust tools.** sudo is /usr/lib/cargo/bin/sudo and cat is /usr/lib/cargo/bin/coreutils/cat. A rule written with /usr/bin paths would never fire.
- **Test every kind of action.** 101220 first covered only "file created" (80790). Modifying an existing sudoers file uses 80781, so the most likely attacker action was invisible until create, modify, chmod and delete were all tested.
- **Visibility has a cost.** 4,341 execve alerts in ~35 minutes, mostly from Wazuh's own control script. Detection value comes from a few precise rules on top of the raw data.
- **Reading a live log file can hit a half-written line.** Scripts that parse alerts.json should skip lines that fail to parse.

## Exercise 16: PowerShell attacks and Script Block Logging
- **Decoded content beats command lines.** Sysmon Event 1 showed `-EncodedCommand VwBy...`; Event 4104 showed `Write-Output ...; whoami`. PowerShell detections should read the script block.
- **Test the built-in rule against every variant.** 92057 caught `-EncodedCommand` and `-e` but not `-enc`, and never fires for a `cmd.exe` parent. Reading the rule file explained it: `enc` is missing from its spelling list.
- **Vendor rules can have bugs.** 91837 searches for `Invoke-Expresion`, so the full spelling never alerts; 91823 matches `Cn` anywhere and fired at level 14 on a Windows script.
- **Sibling rules compete.** Adding the competing built-in IDs to `if_sid` keeps a custom rule in play; when two custom rules matched one script block, the higher-level one was reported.
- **Turning logging off records itself.** The setting is read when PowerShell starts, so the disabling command landed in 4104 even though Sysmon did not see the registry change.
- **New visibility, new noise.** 243 script blocks, 22 alerts, 12 of them noise from the SCA scan, Windows maintenance scripts and a loose built-in regex.
- **Kali's clock was in another timezone** than the Windows VM; convert every time before building a timeline.

## Exercise 17: Full attack chain and incident report
- **Investigate from the alert, not from the attacker's notes.** The first high alert was not the beginning of the attack; the real entry (4 failures and an NTLM success in the same second) was at level 5–6.
- **One layer can hide a gap in another.** The PowerShell Run key was caught only by a 4104 rule. If the attacker had turned off Script Block Logging first, the Sysmon event would have raised nothing.
- **Correlation turns alerts into an incident.** Rule 101400 links a successful brute-force login to any persistence within an hour and raises one level 15 alert instead of several level 12 ones.
- **A regex parent can be wider than it looks.** Built-in 92300 also matches `RunNotification`, written by `sihost.exe` at every logon; the fixed 100300 requires `Run\` or `RunOnce\`.
- **Hidden windows hide your own console.** `-w hidden` in a classic PowerShell window hid the window that launched it: expected attacker behaviour, not a crash.
- **The SIEM is the evidence.** The endpoint lost its logs twice (attacker, then rollover); every logon and account change was still in Wazuh.

## Exercise 18: Alert tuning
- **Build tuning rules from live JSON, never from a guide.** The guide's `signed` field does not exist on Sysmon Event 11, and 61632 has no `parentImage`; both first drafts would never have matched.
- **Real paths beat expected paths.** sudo-rs is `/usr/lib/cargo/bin/sudo`, `python3` is `python3.14`, `nc` is `nc.openbsd`; auditd path rules do not follow symlinks, so `/usr/bin/sudo` would have removed all sudo visibility.
- **Check the time window of your own test.** `ausearch -ts recent` means the last 10 minutes, so the first test showed events from before the change.
- **One passing test does not close an intermittent bug.** The journald first-login loss happened twice and not the third time: a race, so it stays a documented gap with a compensating control (auditd `USER_LOGIN`).
- **Two log sources for the same data is a noise generator.** Adding `auth.log` next to journald would have fixed one race by doubling every sudo, PAM and CRON alert.
- **UIDs are reused.** A new user got the deleted user's UID 1001, and SSH showed the old user's "Last login". `lastlog` is per UID, not per account.
- **Validate before restart, always.** Removing the only rule from a `<group>` left it empty and the manager refused to start; `wazuh-analysisd -t` caught it first.
