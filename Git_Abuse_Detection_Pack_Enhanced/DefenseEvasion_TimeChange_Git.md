---
title: System Time Manipulation Followed by Git Activity
id: time-change-followed-by-git
status: experimental
severity: high
platform: Windows
logsource: DeviceProcessEvents
category: DefenseEvasion
tags:
  - Anti-Forensics
  - Git Abuse
  - Timestomp
  - Supply Chain
mitre:
  - T1070.006
references:
  - Anti-forensic commit backdating
  - PolinRider-aligned workflow tampering
---

# Rule Documentation: System Time Manipulation Followed by Git Activity

## Description
Detects potential anti-forensic behavior where local date or time is changed before or near Git commit or push operations. This pattern is highly suspicious on developer endpoints and can indicate backdating of malicious repository changes.

## Detection Logic
This detection correlates:
- `date`, `time`, or `Set-Date`
- nearby `git commit`, `git push`, `git add`, or `git config`

## Relevant Tables
- `DeviceProcessEvents`

## Search Query
```kql
let TimeChange = DeviceProcessEvents
| where FileName in~ ("cmd.exe", "powershell.exe", "powershell_ise.exe")
| where ProcessCommandLine has_any ("date ", "time ", "Set-Date");
let GitOps = DeviceProcessEvents
| where ProcessCommandLine has_any ("git commit", "git push", "git add", "git config");
TimeChange
| join kind=innerunique GitOps on DeviceId
| where abs(datetime_diff("minute", Timestamp, Timestamp1)) <= 10
| project TimeChangeTime=Timestamp, GitOpTime=Timestamp1, DeviceName, AccountName,
          TimeChangeCommand=ProcessCommandLine, GitCommand=ProcessCommandLine1,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeChangeTime desc
```

## False Positive Tuning
- Exclude IT administration systems used for time synchronization testing.
- Exclude approved lab environments where system time is intentionally manipulated.
- Focus on developer workstations and build hosts for highest fidelity.

## Triage Steps
1. Confirm whether the device is a developer endpoint or CI/CD host.
2. Review exact time-change commands and whether they set explicit historical values.
3. Check for immediate commit amendment, force push, or author identity changes after the time change.
4. Review repository modifications in the same session for hidden execution content or suspicious assets.
5. Confirm whether the user had a legitimate administrative reason to alter local time.

## Investigation Notes
- Very strong signal when paired with Git commit rewrite activity.
