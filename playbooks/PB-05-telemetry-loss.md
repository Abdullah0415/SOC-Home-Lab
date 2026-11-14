# PB-05: Loss of Endpoint Telemetry

[← Playbooks](README.md)

| | |
|---|---|
| **Triggers** | 101550 "Wazuh agent stopped" (level 12, raised from built-in 506 in Exercise 18), agent disconnected, or an agent that is Active but sends no Windows events |
| **MITRE** | T1562.001 Impair Defenses: Disable or Modify Tools, T1529 System Shutdown/Reboot |
| **Priority** | High: while telemetry is down, nothing on that endpoint can be detected |

Lab finding: events written while the agent is down are **never** forwarded later, and crash events (41, 6008) never reach the SIEM. A gap in telemetry is a gap in evidence.

## First five minutes

- [ ] When did events from the agent stop, and when did they resume?
- [ ] Was the stop clean (service stopped, rule 101550) or a crash / power loss (no event at all)?
- [ ] Is the host reachable on the network?

## Investigation

**Is the agent actually sending Windows events?**

```
agent.name:"<host>" and data.win.system.channel:*
```

If only SCA / rootcheck data appears, the agent is connected but not collecting the event channels.

**On the endpoint**

```powershell
Get-Service WazuhSvc, Sysmon64

# What happened during the gap (local logs)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,1001,6005,6006,6008,7036; StartTime='<gap start>'} |
  Sort-Object TimeCreated | Format-Table TimeCreated, Id, ProviderName -AutoSize
```

- 7036 for WazuhSvc = the service was stopped. By whom (Security log, Sysmon Event 1 for `sc.exe` / `net stop`)?
- 41 / 6008 / 1001 = crash or power loss, not an intentional stop.
- Was a log cleared during the gap ([PB-03](PB-03-log-cleared.md))?

**On the manager (if the dashboard is down)**

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
sudo grep "<host>" /var/ossec/logs/ossec.log | tail
```

## Verdict

| Verdict | Evidence |
|---|---|
| **Malicious** | Agent stopped by a user account, close to other suspicious alerts |
| **Operational** | Crash, reboot for updates, or failed agent restart (then fix and document it) |

## Recovery

- [ ] Restart the agent (`Start-Service WazuhSvc`) and confirm Windows events arrive again.
- [ ] Review the endpoint's local logs for the whole gap, since the SIEM never received them.
- [ ] If the stop was intentional and not authorized, treat the host as compromised.

## Record

Gap start and end, cause, how it was confirmed, and what was reviewed locally for the gap.
