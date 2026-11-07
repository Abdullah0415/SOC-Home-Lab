# PB-03: Event Log Cleared

[← Playbooks](README.md)

| | |
|---|---|
| **Trigger** | 100930 (L12): Security log cleared (Event 1102) or another log cleared (Event 104) |
| **MITRE** | T1070.001 Clear Windows Event Logs |
| **Priority** | High: almost never legitimate on a workstation, and usually means someone is hiding earlier activity |

## First five minutes

- [ ] Which **log** was cleared (`win.system.channel`) and by which **account**?
- [ ] Is that account expected to administer this host?
- [ ] Remember: the evidence on the endpoint is gone, but **events already forwarded to the SIEM are not**.

## Investigation

**Reconstruct what was hidden** from the SIEM copy, for the period before the clear:

```
agent.name:"<host>" and rule.level >= 6
```

- Look for logons, new users, persistence, downloads and lateral movement just before the clear.
- Check whether other logs were cleared too (Security, System, Sysmon).
- Check whether the Wazuh agent or Sysmon was stopped around the same time ([PB-05](PB-05-telemetry-loss.md)).
- Identify the tool used: `wevtutil cl`, `Clear-EventLog`, Event Viewer (Sysmon Event 1 for `wevtutil.exe`).

## Verdict

| Verdict | Evidence |
|---|---|
| **True positive** | Clear by a user account, preceded by other suspicious alerts, or several logs cleared together |
| **Benign** | Documented maintenance by an administrator, confirmed with them (rare on endpoints) |

## Containment

- [ ] Treat the host as compromised until the hidden period is explained.
- [ ] Reset the credentials of the account that cleared the log.
- [ ] Preserve the SIEM data for the time window.

## Record

Log name, account, time, tool used, and the activity recovered from the SIEM for the hidden window.
