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

## Tuning

| Lesson | What happened | What I do now | Exercise |
|---|---|---|---|
| Suppress the pattern, not the rule | Not every 92213 alert was the PowerShell policy-test file | Level 0 child rules matching the exact process **and** file / command line / parent | 8 |
| A suppression needs a negative test | Proved `sdbinst -m -bg` from an admin shell still alerts after rule 100710 | Every suppression ships with a test showing real activity still alerts | 8 |

## Log pipeline and visibility

| Lesson | What happened | What I do now | Exercise |
|---|---|---|---|
| "No alerts" is not "no activity" | A negative test seemed to pass, but the agent had stopped sending Windows logs | Check that events are arriving (archives) before trusting a result | 8 |
| "Active" is not "sending" | After a crash the agent showed Active but sent only SCA and rootcheck data | Verify real EventChannel events, restart the agent if needed | 11 |
| Agent down = permanent blind spot | An event written while the agent was stopped was never recovered after restart | Treat an agent stop as a high-severity incident | 11 |
| Rule gap vs visibility gap | Crash events (41, 6008) never reached the manager at all | Do not ship rules for data that never arrives; document the gap instead | 11 |
| Same Event ID, different meaning | Event 1001 exists in System (bugcheck) and Application (Windows Error Reporting) | Filter by channel and provider, not just Event ID | 10 |
| Some systems do not log what you expect | sudo-rs on Ubuntu 26.04 did not log denied `sudo` attempts | Verify the log exists before planning a detection; auditd as a fix | 9 |

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

