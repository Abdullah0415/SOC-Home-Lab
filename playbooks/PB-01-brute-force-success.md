# PB-01: Brute Force That Succeeded (SSH / RDP)

[← Playbooks](README.md)

| | |
|---|---|
| **Triggers** | 100800 (SSH, L14), 101010 (RDP, L14), 101020 (RDP after a few failures, L12), built-in 40112 (SSH, L12), 101100 (auto-block, L8) |
| **MITRE** | T1110.001 Password Guessing, T1078 Valid Accounts, T1021.001 Remote Desktop Protocol |
| **Priority** | Critical: an attacker very likely holds a working password and is (or was) logged in |

## First five minutes

- [ ] Note the **source IP**, **target account**, **host** and **time** from the alert.
- [ ] Is the source IP internal, a known admin workstation, or unknown?
- [ ] Is the account a real user, a service account or an admin?
- [ ] Is the session still active?
- [ ] **If the IP was auto-blocked (101100):** do not assume the attack failed. In Exercise 14 the attacker logged in one second before the block. Check the source log for a successful login:

```bash
sudo journalctl --since "<block time - 2 min>" | grep -i "accepted"
```

## Investigation

**All activity from the source IP**

```
data.srcip:"<ip>" or data.win.eventdata.ipAddress:"<ip>"
```

**Failure pattern before the success** (count, time span, accounts tried):

- SSH: rules 5760 / 5503 / 5763
- RDP: rules 60122 (4625, logon type 3 because NLA checks the password first) and 60204

**What happened after the login**

| SSH (Linux) | RDP (Windows) |
|---|---|
| `last -i`, `who` | `query user` (or `quser`) |
| `grep "<ip>" /var/log/auth.log` | Sysmon Event 1 for the account after the logon time |
| `sudo` attempts (note: sudo-rs may not log denials) | Rules 100200, 100300, 100400, 100600, 100910 on the same host |
| New users / keys: `~/.ssh/authorized_keys` | New users (4720), group changes (4732) |

## Verdict

| Verdict | Evidence |
|---|---|
| **True positive** | Unknown source, many failures then success, followed by discovery or persistence activity |
| **Benign** | Known admin who mistyped the password several times, from their usual workstation, confirmed with them |

A "known user" is not enough on its own: confirm with the person through a separate channel.

## Containment

- [ ] Disable or lock the account and reset its password.
- [ ] End active sessions (`logoff <id>` on Windows, `pkill -u <user>` on Linux).
- [ ] Block the source IP (firewall or Wazuh Active Response). An automatic block is temporary (180 s in the lab); make it permanent if the activity is malicious.
- [ ] On Windows, the stock `netsh` response does not work for logon alerts (no `srcip`), so block manually.
- [ ] Hunt for persistence the attacker may have created ([PB-02](PB-02-persistence.md)).

## Record

Source IP, account, number of failures, time of success, session duration, commands run after login, containment actions and times.
