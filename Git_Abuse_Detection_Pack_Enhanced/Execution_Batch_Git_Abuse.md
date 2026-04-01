# Rule : Batch Script Driven Git History Manipulation

## Description
Detects batch or command scripts invoking chained Git history rewrite operations, including commit amendment, verification bypass, force push, and local identity changes. This is useful for identifying attacker automation tooling in Windows developer environments.

## Detection Logic
This detection looks for:
- `.bat` or `.cmd` execution
- Git amend / push / config patterns
- optional date/time manipulation in the same command line

## Relevant Tables
- `DeviceProcessEvents`

## Search Query
```kql
DeviceProcessEvents
| where FileName in~ ("cmd.exe", "powershell.exe")
| where ProcessCommandLine has_any (".bat", ".cmd")
| where ProcessCommandLine has_any ("git commit --amend", "git push -f", "--no-verify", "git config --local")
    or ProcessCommandLine has_any ("date ", "time ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA1
| order by Timestamp desc
```

## False Positive Tuning
- Exclude sanctioned release or migration scripts after verification.
- Review path allowlists carefully; avoid broad exclusions for developer script folders.
- Prioritize scripts executed from repository roots, temp directories, downloads, or user profile paths.

## Triage Steps
1. Retrieve and review the batch file contents.
2. Identify whether it captures Git metadata, changes time, amends commits, or force pushes.
3. Determine which repositories and branches were affected.
4. Check whether the script executed shortly before suspicious repository changes or malware execution.
5. Review parent-child process chains for developer IDEs, shells, or automation frameworks.

## Investigation Notes
- High concern when scripts restore original time after amending commits.
