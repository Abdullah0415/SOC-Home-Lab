# PB-02: Persistence on a Windows Endpoint

[← Playbooks](README.md)

| | |
|---|---|
| **Triggers** | 100100 new local user, 100300 Run key, 100400 scheduled task, 100910 Startup folder file |
| **MITRE** | T1136.001, T1547.001, T1053.005 |
| **Priority** | High: the attacker is preparing to come back after a reboot or password change |

## First five minutes

- [ ] What was created: user, Run key value, scheduled task or Startup file? Note its exact name and path.
- [ ] Which **account** and **process (image + PID)** created it?
- [ ] Was it created by an admin tool during a known change window?

## Investigation

**Inspect the artifact on the endpoint**

```powershell
# Run keys
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

# Scheduled task (action, trigger, author)
schtasks /query /tn "<task name>" /v /fo list

# Startup folders
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

# New local users
Get-LocalUser | Sort-Object -Property LastLogon
```

**Build the chain:** in Wazuh, filter the host and the creating process ID. The same PID creating a Run key, a task and a Startup file is one attacker session, not three events.

- What does the persistence **launch**? Inspect the target file (path, hash, signature) without running it.
- What happened **before** it: a successful brute force ([PB-01](PB-01-brute-force-success.md)), lateral movement or a download ([PB-04](PB-04-lateral-movement-tool-transfer.md))?

## Verdict

| Verdict | Evidence |
|---|---|
| **True positive** | Disguised name (e.g. "Updater", "WindowsUpdateHelper"), launches a script or binary from a user-writable path, created right after suspicious logon activity |
| **Benign** | Signed software installer, IT deployment tool, documented change |

## Containment

- [ ] Remove the Run key / task / Startup file / user (after collecting evidence).
- [ ] Quarantine the launched file and record its hash.
- [ ] Reset credentials of the account that created it.
- [ ] Check other endpoints for the same artifact name.

## Record

Artifact type, name and path, creating account and process, what it launches, file hash, removal time.
