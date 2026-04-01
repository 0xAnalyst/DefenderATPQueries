---
title: Suspicious Git Commit Rewrite with Verification Bypass
id: git-commit-amend-noverify
status: experimental
severity: high
platform: Windows
logsource: DeviceProcessEvents
category: Execution
tags:
  - Defense Evasion
  - Git Abuse
  - Supply Chain
  - Anti-Forensics
mitre:
  - T1070.006
  - T1036
references:
  - PolinRider campaign research
  - Supply chain commit history tampering patterns
---

# Rule Documentation: Suspicious Git Commit Rewrite with Verification Bypass

## Description
Detects Git history rewrite activity where a user amends the latest commit while bypassing local verification hooks. This behavior can be used to preserve the appearance of legitimate development activity while modifying repository contents.

## Detection Logic
This detection looks for:
- `git commit --amend`
- `--no-verify`
- Shell or batch execution around Git operations

## Relevant Tables
- `DeviceProcessEvents`

## Search Query
```kql
DeviceProcessEvents
| where ProcessCommandLine has "git commit --amend"
   or (ProcessCommandLine has "git commit" and ProcessCommandLine has "--amend")
| extend HasNoVerify = iff(ProcessCommandLine has "--no-verify", "Yes", "No")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          FolderPath, SHA1, HasNoVerify, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

## False Positive Tuning
- Exclude approved release engineering or repository maintenance hosts.
- Exclude sanctioned administrator accounts that regularly perform controlled history rewrites.
- Add allowlists for internal automation that legitimately amends commits in ephemeral test repositories.

## Triage Steps
1. Review the full command line for `--no-verify`, `--amend`, and unusual working directories.
2. Check whether the same user also performed `git push -f` or changed local Git identity settings.
3. Review nearby file modifications for `.vscode/tasks.json`, hidden scripts, or non-standard executable content.
4. Validate whether the repository and branch are business-critical or public-facing.
5. Confirm whether the activity originated from a developer workstation, build host, or administrative automation node.

## Investigation Notes
- High concern when followed by force-push activity.
- High concern when paired with system time changes or local Git user identity changes.
