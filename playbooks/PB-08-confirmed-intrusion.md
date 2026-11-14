# PB-08: Confirmed Intrusion – Brute-Force Login Followed by Persistence

[← Playbooks](README.md)

| | |
|---|---|
| **Trigger** | 101400 (L15): persistence (100100, 100300, 100400 or 91844) within 1 hour of a successful brute-force login (101010 or 101020) |
| **MITRE** | T1110.001 Password Guessing, T1021.001 RDP, T1078 Valid Accounts, T1547.001 / T1053.005 / T1136.001 Persistence |
| **Priority** | Critical: treat as an active intrusion, not a single alert |
| **Worked example** | [Incident Report IR-01](../docs/incident-report-01.md) (Exercise 17) |

## First five minutes

- [ ] Note host, time and the persistence type from the 101400 description.
- [ ] Find the login it correlated with: `agent.name:<host> and rule.id:(101010 or 101020)` in the hour before. Note the **source IP** and **account**.
- [ ] Is the attacker still logged in? On the host: `quser`.
- [ ] Is the account an administrator? (`net localgroup Administrators`)

## Contain first

1. Disable the compromised account and any account created in the last hour: `net user <name> /active:no`.
2. End the attacker's session: `logoff <ID>` from `quser`.
3. Block the source IP or disable RDP (`fDenyTSConnections` = 1 and the "Remote Desktop" firewall group), or isolate the host.

## Scope the intrusion

Search the host from the first failed logon to now, grouped by rule (see the timeline script in Exercise 17):

| Look for | Query |
|---|---|
| Every action of the account | `agent.name:<host> and <account>` |
| Execution | `rule.id:(101300 or 101310 or 101315 or 101320 or 100200)` |
| All persistence | `rule.id:(100100 or 100300 or 100400 or 91844 or 60154 or 100910)` |
| Defense evasion | `rule.id:(101330 or 100930 or 101550)` |
| Downloads | `data.win.eventdata.scriptBlockText:*http*` |

- **Do not rely on the endpoint's logs:** they may be cleared (100930) or overwritten. Use the SIEM.
- **Check below level 10:** the entry point may be only 60122 (L5) and 92652 / 101000 (L6).

## Eradicate

- [ ] Delete every account the attacker created and remove its profile (`Get-CimInstance Win32_UserProfile | ... | Remove-CimInstance`).
- [ ] Remove scheduled tasks (`schtasks /delete`), Run keys (HKLM and every user's HKCU) and Startup folder items.
- [ ] Delete downloaded or dropped files.
- [ ] Restore anything switched off: Script Block Logging (`EnableScriptBlockLogging` = 1), Sysmon, Wazuh agent.
- [ ] Reset the password of the compromised account, or delete it.

## Recover and report

- [ ] Verify: no unknown accounts, tasks, Run keys or sessions; telemetry flowing again.
- [ ] Write the incident report: timeline (one clock), IOCs, root cause, detection coverage, response, recommendations.
- [ ] Turn every missed step into a rule, a tuning item or a documented gap.
