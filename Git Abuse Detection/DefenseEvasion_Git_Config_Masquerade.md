# Rule : Git Author Masquerading via Local User Config Changes

## Description
Detects local Git configuration changes that set author name or email immediately before commit operations. In malicious scenarios, this can be used to preserve the appearance of trusted contributor identity.

## Detection Logic
This detection looks for:
- `git config --local user.name`
- `git config --local user.email`

## Relevant Tables
- `DeviceProcessEvents`

## Search Query
```kql
DeviceProcessEvents
| where ProcessCommandLine has "git config --local"
| where ProcessCommandLine has_any ("user.name", "user.email")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## False Positive Tuning
- Exclude developer onboarding scripts that set identity once during initial environment setup.
- Exclude golden images or administrative build templates after validation.
- Prioritize repeated changes or changes immediately preceding amend/force-push activity.

## Triage Steps
1. Review prior and subsequent Git activity by the same user on the same device.
2. Determine whether the local identity matches an expected corporate or contractor account.
3. Check for commit amendment, force push, or verification bypass in the same session.
4. Review whether the actor attempted to match the identity of another trusted developer.
5. Validate whether the repository was changed after the local identity update.

## Investigation Notes
- Particularly useful for identifying impersonation in contractor or third-party development scenarios.
