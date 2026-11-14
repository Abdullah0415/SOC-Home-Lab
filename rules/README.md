# Wazuh Rules

[← Back to README](../README.md)

[`local_rules.xml`](local_rules.xml) is an exact copy of the custom rule file running on the lab's Wazuh manager (`/var/ossec/etc/rules/local_rules.xml`). It contains 23 detection rules, 1 response-visibility rule (101100), 6 false-positive suppression rules (level 0), 4 severity-correction rules (level 3) and 1 overwritten built-in rule (91823). Rule 100001 is the example rule that Wazuh ships in this file by default and is not part of the lab.

For what each rule detects, its parent rule, MITRE mapping and the exercise that proved it, see [docs/02-detection-rules.md](../docs/02-detection-rules.md). For the tuning rules and their positive and negative tests, see [docs/04-tuning.md](../docs/04-tuning.md).

## Rule ID ranges

| Range | Purpose |
|---|---|
| 100100 – 100600 | Windows detections (account creation, discovery, persistence, lateral movement, tool transfer) |
| 100700 – 100710 | False-positive suppression (level 0) |
| 100800 | Linux SSH |
| 100900 – 100910 | File integrity monitoring |
| 100930 | Defense evasion |
| 101000 – 101020 | Windows RDP |
| 101100 | Active Response visibility |
| 101200 – 101220 | Linux privilege escalation (auditd) |
| 101300 – 101330 | PowerShell attacks (Sysmon 1 and Event 4104) |
| 101400 | Incident correlation |
| 101500 – 101530 | Tuning: false-positive suppression (level 0) |
| 101540, 101560 – 101580 | Tuning: severity corrections for benign logon and Edge activity (level 3) |
| 101550 | Wazuh agent stopped (level 12) |
| 91823 | Built-in rule overwritten (`overwrite="yes"`) to fix its regex |

## Deploy

```bash
# On the Wazuh manager
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
sudo cp local_rules.xml /var/ossec/etc/rules/local_rules.xml

# Validate before restarting (must report no errors)
sudo /var/ossec/bin/wazuh-analysisd -t

# Restart
sudo /var/ossec/bin/wazuh-control restart
```

## Test

```bash
# Paste a raw log line or event JSON to see which rule matches
sudo /var/ossec/bin/wazuh-logtest
```

Every rule in this file was also tested by reproducing the real attack in the lab and confirming the alert on the dashboard (screenshots in the matching [exercise](../README.md#-contents)).

## Notes

- Several rules are children of built-in rules (`if_sid`), so they depend on the default Wazuh 4.x ruleset and the Sysmon / Windows decoders.
- Rules 101200 – 101220 need auditd on the manager ([config](../config/)); rules 101310 – 101330 need PowerShell Script Block Logging and the 4104 `<localfile>` on the agent ([config/powershell-localfile.xml](../config/powershell-localfile.xml)).
- Paths and names such as `C:\FIM-Test\Finance` are lab-specific and would be replaced with real sensitive locations in production.
- Windows paths in the regexes use `\\+` because Wazuh stores them with doubled backslashes.
- The overwrite of 91823 must keep the built-in parent, options and MITRE mapping; re-check it after every Wazuh upgrade, since an updated built-in rule would be silently replaced.
