# Rule : Detection of GetAsyncKeyState API Call

## Description
This detection rule identifies suspicious usage of the `GetAsyncKeyState` API call. The `GetAsyncKeyState` function is used to determine whether a key is currently pressed or was pressed after a previous call to this function, which can be leveraged by keylogging malware to capture keystrokes. Legitimate software may use this function, but it is often exploited by malicious actors to monitor and capture user input, leading to unauthorized access to sensitive information. According to the MITRE ATT&CK framework, this technique falls under "Input Capture: Keylogging" (T1056.001).

This rule helps detect and audit suspicious usage of `GetAsyncKeyState`, providing an early warning for potential keylogging activities.

- [MITRE ATT&CK: Input Capture: Keylogging](https://attack.mitre.org/techniques/T1056/001/)

## Detection Logic
- Monitors `DeviceEvents` for events where:
  - The `ActionType` is "GetAsyncKeyStateApiCall".
  - The `InitiatingProcessVersionInfoFileDescription` is not "Adobe Acrobat".
  - The `InitiatingProcessVersionInfoProductName` is not "QuickTime".
  - The `InitiatingProcessVersionInfoCompanyName` is not "Adobe Systems Incorporated".
  - The `InitiatingProcessVersionInfoCompanyName` is not "MAXON Computer GmbH".
  - The `InitiatingProcessVersionInfoCompanyName` is not "Adobe".

## Tags
- Keylogging
- GetAsyncKeyState
- Input Capture
- API Call
- MITRE ATT&CK T1056.001
- Suspicious Activity

## Search Query
```kql
DeviceEvents
| where ActionType == "GetAsyncKeyStateApiCall"
| where InitiatingProcessVersionInfoFileDescription != "Adobe Acrobat"
| where InitiatingProcessVersionInfoProductName != "QuickTime"
| where InitiatingProcessVersionInfoCompanyName != "Adobe Systems Incorporated"
| where InitiatingProcessVersionInfoCompanyName != "MAXON Computer GmbH"
| where InitiatingProcessVersionInfoCompanyName != "Adobe"
```
