# Configuration

[← Back to README](../README.md)

Configuration snippets taken from the running lab. Each file has a comment at the top saying exactly where it goes.

| File | Where it goes | What it does | Exercise |
|---|---|---|---|
| [`active-response.xml`](active-response.xml) | Manager `/var/ossec/etc/ossec.conf` | Whitelist plus two Active Response blocks: `firewall-drop` on SSH brute force (5763) and `netsh` on RDP brute force (101010), 180 s timeout. Both are **disabled** after testing | 14 |
| [`auditd-wazuh-lab.rules`](auditd-wazuh-lab.rules) | Manager `/etc/audit/rules.d/wazuh-lab.rules`, then `sudo augenrules --load` | Audit keys used by Wazuh: `audit-wazuh-c` (execution of `sudo`, `su`, `bash`, `curl`, `wget`, `nc`, `python3` by login users), `audit-wazuh-r` (`/etc/shadow` reads), `audit-wazuh-w` (sudoers changes) | 15, tuned in 18 |
| [`auditd-localfile.xml`](auditd-localfile.xml) | Manager `/var/ossec/etc/ossec.conf` | Reads `/var/log/audit/audit.log` with `log_format audit` | 15 |
| [`powershell-localfile.xml`](powershell-localfile.xml) | Agent `C:\Program Files (x86)\ossec-agent\ossec.conf` | Collects PowerShell Event 4104 (decoded script blocks) only | 16 |

## Notes

- **auditd paths are real paths.** Path rules do not follow symlinks. On Ubuntu 26.04 `sudo` is sudo-rs at `/usr/lib/cargo/bin/sudo`, `python3` is `/usr/bin/python3.14` and `nc` is `/usr/bin/nc.openbsd`. On another system, resolve each one first:

  ```bash
  for b in sudo su bash curl wget nc python3; do echo "$b -> $(readlink -f $(command -v $b))"; done
  ```

- After changing the audit rules, check the kernel list with `sudo auditctl -l` and test with a fixed start time (`ausearch -k audit-wazuh-c -ts <HH:MM:SS> -i`), not `-ts recent`, which also shows the 10 minutes before the change.
- Endpoint settings that are not in a file here (Exercise 18): Windows Time synced to `time.windows.com` (`w32tm /config /manualpeerlist:"time.windows.com,0x9" /syncfromflags:manual /update`) and the Security log raised to 200 MB (`wevtutil sl Security /ms:209715200`).
