# PB-06: Linux Privilege Escalation Attempt

**Triggers:** 101200 (sudo by non-admin, L10), 101210 (/etc/shadow read attempt, L12), 101220 (sudoers changed, L12)
**MITRE:** T1548.003 Sudo and Sudo Caching · T1003.008 /etc/passwd and /etc/shadow · T1078 Valid Accounts
**Data source:** auditd (`/var/log/audit/audit.log`) via Wazuh, plus auth/journald logs
**Related:** PB-01 (SSH brute force), Exercise 9, Exercise 15

## 1. Triage (first 5 minutes)
1. Open the alert JSON and note:
   - `data.audit.auid`: the **login** user (who really did it, even after sudo)
   - `data.audit.uid` / `euid`: who the process ran as
   - `data.audit.exe`: the program used
   - `data.audit.success`: did it work?
   - `data.audit.file.name` (101220): which sudoers file
2. Map the auid to a user: `getent passwd <auid>`.
3. Is this user expected to use sudo or touch sudoers? (Change ticket, known admin?)

| Situation | Severity |
|---|---|
| 101200 or 101210 with `success: no` from a normal user | Suspicious: someone is probing |
| 101210 with `success: yes` from a non-admin | **Critical**: password hashes may be stolen |
| 101220 by anyone without a change ticket | **Critical**: possible persistence |
| Any of these shortly after an SSH login from an unusual IP | **Critical**: likely compromised account |

## 2. Investigate
1. **How did the user get in?** Search the same host around the alert time:
   `agent.name:<host> and (rule.id:5715 or rule.id:5760 or rule.id:40112 or rule.id:100800)`
   Look for brute force followed by success (PB-01).
2. **Do not trust a missing login alert.** Check the source too:
   `journalctl --since "<time - 10 min>" | grep -i "accepted"`
   (Known gap: the first login of a newly created user may not raise 5715.)
3. **What else did the user run?**
   `sudo ausearch -ua <auid> -i --start <time>`, or on the dashboard:
   `data.audit.auid:<auid> and rule.groups:audit`
4. **For 101220:** read the sudoers file (`sudo cat <file>`) and check for new `ALL=(ALL)` or `NOPASSWD` lines. Run `sudo visudo -c`.
5. **For 101210 with success yes:** treat every password hash on the host as exposed.

## 3. Contain
- Lock the account: `sudo usermod -L <user>` and kill its sessions: `sudo pkill -KILL -u <user>`.
- Block the source IP if the login came from outside (see PB-01 / Active Response).
- For 101220: move the unknown sudoers file out of `/etc/sudoers.d/` (keep a copy as evidence), then `sudo visudo -c`.

## 4. Eradicate and recover
- Reset the passwords of every account on the host if /etc/shadow was read successfully.
- Remove unknown sudoers entries, SSH keys (`~/.ssh/authorized_keys`), cron jobs and new users.
- Confirm auditd and the Wazuh agent are still running (`systemctl status auditd`, `wazuh-control status`).

## 5. Lessons / tuning
- Expected admin sudo should not reach 101200. If a new admin is added, update the admin list (CDB list in production; uid 1000 in this lab).
- If 101210 fires on a legitimate program, add its exe to the exclusion with evidence from the alert JSON, never by guessing.
