---
title: Suspicious Git Force Push Activity
id: git-force-push-abuse
status: experimental
severity: medium
platform: Windows
logsource: DeviceProcessEvents
category: Execution
tags:
  - Git Abuse
  - Supply Chain
  - Repo Poisoning
  - Defense Evasion
mitre:
  - T1070
  - T1098
references:
  - Repo poisoning tradecraft
  - Supply chain compromise investigations
---

# Rule Documentation: Suspicious Git Force Push Activity

## Description
Detects force-push behavior that may indicate rewritten commit history being pushed upstream. This becomes especially suspicious when paired with commit amendment, verification bypass, or stealthy workspace/task modifications.

## Detection Logic
This detection looks for:
- `git push -f`
- `git push --force`
- `git push -uf`
- `git push --force-with-lease`

## Relevant Tables
- `DeviceProcessEvents`

## Search Query
```kql
DeviceProcessEvents
| where ProcessCommandLine has "git push"
| where ProcessCommandLine has_any (" -f", "--force", "-uf", "--force-with-lease")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## False Positive Tuning
- Exclude dedicated repository migration projects and mirrored repositories.
- Exclude controlled release-engineering workflows after validation.
- Scope to production, public, or sensitive repositories first for highest signal.

## Triage Steps
1. Determine which repository and branch were targeted.
2. Verify whether this force push followed a `git commit --amend` or other history rewrite.
3. Review whether repository protections should have prevented this action.
4. Check for adjacent suspicious files, hidden tasks, or obfuscated payloads added in the same timeframe.
5. Identify whether the push originated from an unmanaged or newly onboarded developer device.

## Investigation Notes
- Stronger signal when combined with `--no-verify`.
- High value for scoping supply chain compromise across developer endpoints.
