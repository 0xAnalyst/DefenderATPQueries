# Rule : Detection of PsExec and WMI Child Processes Through ASR

## Description
This detection rule identifies child processes created by PsExec and WMI that have been audited or bypassed by Advanced Security Rules (ASR), excluding `shutdown.exe`. Monitoring PsExec and WMI child processes is critical because they are commonly used by attackers to execute commands and scripts remotely. These tools are often leveraged for lateral movement and executing malicious payloads on target systems.

This rule helps identify suspicious activity involving PsExec and WMI, excluding legitimate use cases such as system shutdown operations.

## Detection Logic
- Monitors `DeviceEvents` for events where:
  - The `ActionType` starts with "AsrPsexecWmiChildProcessAudited" or "AsrPsexecWmiChildProcessWarnBypassed".
  - The `FileName` is not "shutdown.exe".

## Tags
- PsExec
- WMI
- Remote Execution
- Lateral Movement
- Advanced Security Rules (ASR)
- Suspicious Activity

## Search Query
```kql
DeviceEvents
| where ActionType startswith "AsrPsexecWmiChildProcessAudited" or ActionType startswith "AsrPsexecWmiChildProcessWarnBypassed" 
| where FileName != "shutdown.exe"
```
# Notes
