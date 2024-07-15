# Rule : Detection of Office Child Processes Through ASR

## Description
This detection rule identifies child processes spawned by Microsoft Office applications that have been audited by Advanced Security Rules (ASR), excluding `onedrive.exe`. Monitoring for child processes created by Office applications is crucial because malicious actors often use Office macros to launch additional processes to execute malicious payloads. By excluding known and trusted processes like OneDrive, this rule focuses on identifying potentially suspicious activities that could compromise the system.

This rule helps identify and audit unusual child processes initiated by Office applications, providing an early warning for potential malicious activities.

## Detection Logic
- Monitors `DeviceEvents` for events where:
  - The `ActionType` is "AsrOfficeChildProcessAudited".
  - The `FileName` is not "onedrive.exe".

## Tags
- Office Security
- Child Processes
- Macro Security
- Malware
- Advanced Security Rules (ASR)
- Suspicious Activity

## Search Query
```kql
DeviceEvents 
| where ActionType == "AsrOfficeChildProcessAudited"
| where FileName != "onedrive.exe"
```
