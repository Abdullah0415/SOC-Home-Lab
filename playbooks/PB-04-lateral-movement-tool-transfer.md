# PB-04: Lateral Movement and Tool Transfer

[← Playbooks](README.md)

| | |
|---|---|
| **Triggers** | 100500 network logon type 3 (L12), 100600 PowerShell web download (L12) |
| **MITRE** | T1021 Remote Services, T1105 Ingress Tool Transfer |
| **Priority** | High: an attacker is moving between hosts or bringing tools onto one |

## First five minutes

- [ ] **100500:** source IP, account, target host. Is the source a server or admin workstation that normally connects here?
- [ ] **100600:** full command line, URL or IP downloaded from, output file path, user and parent process.

## Investigation

**Lateral movement (100500)**

- Is the account used from this source normally? Compare with previous days.
- Were there failed logons from the same IP first (60122 / 60204)?
- What ran on the target right after the logon (Sysmon Event 1, services, scheduled tasks)?

**Tool transfer (100600)**

```
agent.name:"<host>" and data.win.system.eventID:3
```

- Sysmon Event 3 shows the network connection made by PowerShell (destination IP and port).
- Sysmon Event 11 shows the file written. Collect its path and hash and check its reputation.
- Who launched PowerShell (parent process)? An interactive user, a script, or another suspicious process?

## Verdict

| Verdict | Evidence |
|---|---|
| **True positive** | Unknown source, new tool downloaded from an IP rather than a known domain, followed by execution or persistence |
| **Benign** | Management server, backup or monitoring system with a known schedule; admin downloading from a trusted vendor site |

Type 3 logons are common (file shares, management tools), so this verdict depends on **baselining** the normal sources.

## Containment

- [ ] Isolate the affected host(s) from the network.
- [ ] Block the download URL / IP.
- [ ] Quarantine the downloaded file and reset the account used.

## Record

Source and target hosts, account, command line, URL or IP, file path and hash, sequence of hosts touched.
