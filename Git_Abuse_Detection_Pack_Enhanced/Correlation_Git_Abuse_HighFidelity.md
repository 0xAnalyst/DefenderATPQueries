---
title: High-Fidelity Correlation for Git History Manipulation
id: correlated-git-history-manipulation
status: experimental
severity: high
platform: Windows
logsource: DeviceProcessEvents
category: Correlation
tags:
  - Correlation
  - Git Abuse
  - Supply Chain
  - Anti-Forensics
mitre:
  - T1070.006
  - T1036
  - T1059.003
references:
  - PolinRider-aligned anti-forensics
  - Supply chain developer compromise investigations
---

# Rule Documentation: High-Fidelity Correlation for Git History Manipulation

## Description
Correlates the strongest Git abuse indicators on the same device: local Git identity changes, commit amendment, verification bypass, force push, and optional time manipulation. This is intended as a high-confidence analytic for stealth repository tampering.

## Detection Logic
This correlation looks for:
- local Git identity change
- commit amendment
- force push
- optional time manipulation

## Relevant Tables
- `DeviceProcessEvents`

## Search Query
```kql
let GitConfig = DeviceProcessEvents
| where ProcessCommandLine has "git config --local"
| where ProcessCommandLine has_any ("user.name", "user.email")
| project DeviceId, DeviceName, AccountName, GitConfigTime=Timestamp, GitConfigCmd=ProcessCommandLine;

let GitAmend = DeviceProcessEvents
| where ProcessCommandLine has "git commit"
| where ProcessCommandLine has "--amend"
| project DeviceId, AmendTime=Timestamp, AmendCmd=ProcessCommandLine;

let GitPush = DeviceProcessEvents
| where ProcessCommandLine has "git push"
| where ProcessCommandLine has_any ("-f", "--force", "-uf", "--force-with-lease")
| project DeviceId, PushTime=Timestamp, PushCmd=ProcessCommandLine;

let TimeChange = DeviceProcessEvents
| where FileName in~ ("cmd.exe", "powershell.exe", "powershell_ise.exe")
| where ProcessCommandLine has_any ("date ", "time ", "Set-Date")
| project DeviceId, TimeChangeTime=Timestamp, TimeChangeCmd=ProcessCommandLine;

GitConfig
| join kind=inner GitAmend on DeviceId
| join kind=inner GitPush on DeviceId
| join kind=leftouter TimeChange on DeviceId
| where AmendTime between (GitConfigTime .. GitConfigTime + 30m)
| where PushTime between (AmendTime .. AmendTime + 30m)
| where isempty(TimeChangeTime) or TimeChangeTime between (GitConfigTime - 15m .. PushTime + 15m)
| project DeviceName, AccountName, GitConfigTime, GitConfigCmd, AmendTime, AmendCmd,
          PushTime, PushCmd, TimeChangeTime, TimeChangeCmd
| order by PushTime desc
```

## False Positive Tuning
- Exclude tightly controlled migration or repository administration workflows.
- Restrict initially to developer endpoints and privileged engineering hosts.
- Tune with known sanctioned automation accounts and repository maintenance windows.

## Triage Steps
1. Validate whether the sequence occurred on a managed developer workstation or build host.
2. Identify the repository and branch tied to the activity.
3. Review nearby file and process events for hidden tasks, obfuscated scripts, or non-standard executable assets.
4. Determine whether the same actor performed suspicious network or IDE-triggered execution.
5. Escalate immediately if the sequence involves public repositories, external contractors, or unmanaged devices.

## Investigation Notes
- Designed as the highest-value production analytic in this pack.
