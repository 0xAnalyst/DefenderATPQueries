# Rule : Detection of Office Macro Win32 API Calls Audited

## Description
This detection rule identifies audited events where Office Macros make Win32 API calls. Monitoring for such API calls is crucial because macros can be used to execute malicious code on the system. Malicious actors often exploit Office macros to run unauthorized scripts or binaries by leveraging Win32 API calls, which can lead to system compromise or data exfiltration.

This rule monitors for audited actions related to Office macros making Win32 API calls, helping to identify potentially malicious macros that could compromise the system.

## Detection Logic
- Monitors `DeviceEvents` for events where:
  - The `ActionType` is "AsrOfficeMacroWin32ApiCallsAudited".

## Tags
- Office Security
- Macro Security
- Win32 API Calls
- Malware
- Suspicious Activity

## Search Query
```kql
DeviceEvents 
| where ActionType == "AsrOfficeMacroWin32ApiCallsAudited"
```
## Note
Exclude trusted file names as this might get noisy
