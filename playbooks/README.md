# Investigation Playbooks

[← Back to README](../README.md)

Short, practical checklists for triaging the alerts this lab produces. Each playbook follows the same structure: trigger, first five minutes, investigation, verdict, containment, and what to record.

| ID | Playbook | Triggered by |
|---|---|---|
| PB-01 | [Brute force that succeeded (SSH / RDP)](PB-01-brute-force-success.md) | 100800, 101010, 40112 |
| PB-02 | [Persistence on a Windows endpoint](PB-02-persistence.md) | 100100, 100300, 100400, 100910 |
| PB-03 | [Event log cleared](PB-03-log-cleared.md) | 100930 |
| PB-04 | [Lateral movement and tool transfer](PB-04-lateral-movement-tool-transfer.md) | 100500, 100600 |
| PB-05 | [Loss of endpoint telemetry](PB-05-telemetry-loss.md) | 506, missing events from an agent |
| PB-06 | [Linux privilege escalation attempt](PB-06-linux-privilege-escalation.md) | 101200, 101210, 101220 |
| PB-07 | [Suspicious PowerShell](PB-07-suspicious-powershell.md) | 101300, 101310, 101315, 101320, 101330, 92057 |

**General rules for every playbook**

- Record times with their timezone (server logs UTC, dashboard local time).
- Pivot on the source IP, the account and the process ID: they tie separate alerts into one attack chain.
- Before concluding "nothing happened", confirm the log pipeline was working at that time ([PB-05](PB-05-telemetry-loss.md)).
- In the lab, all containment steps are simulated or performed on lab-only accounts.
