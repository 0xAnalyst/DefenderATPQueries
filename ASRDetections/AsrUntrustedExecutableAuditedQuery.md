# Rule : Detection of Untrusted Executables in User Folders

## Description
This detection rule identifies untrusted executables within user directories that have been audited by Advanced Security Rules (ASR). Monitoring for untrusted executables is crucial because they can indicate the presence of malware or unauthorized software introduced into the system by malicious actors. This rule helps identify newly observed, globally rare executables within user folders that might have been introduced through various attack vectors.

This rule monitors for audited actions related to untrusted executables in user directories, focusing on files that are new and have low global prevalence.

## Detection Logic
- Monitors `DeviceEvents` for events where:
  - The `ActionType` is "AsrUntrustedExecutableAudited".
  - The `FolderPath` contains "users".
  - The file has been seen globally within the last 3 days and has a global prevalence of less than or equal to 1.

## Tags
- Untrusted Executables
- User Directories
- Malware
- Suspicious Activity
- Advanced Security Rules (ASR)

## Search Query
```kql
DeviceEvents
| where FolderPath contains "users" and ActionType == "AsrUntrustedExecutableAudited"
| project Timestamp, ReportId, DeviceId, ProcessCommandLine, FileName, FolderPath, InitiatingProcessSHA1, InitiatingProcessFileName, SHA1
| invoke FileProfile("SHA1")
| where GlobalFirstSeen > ago(3d) and GlobalPrevalence <= 1
```
## Notes
This needs a bit of fine tunning to be enabled as a detection rule
