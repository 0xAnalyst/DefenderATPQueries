# Rule : Detection of NtMapViewOfSection Remote API Call

## Description
This detection rule identifies suspicious usage of the `NtMapViewOfSection` function for remote API calls. The `NtMapViewOfSection` function allows a process to map a view of a section into its address space, which can be used for legitimate purposes but can also be exploited by malicious actors for process injection. This technique is often used to execute arbitrary code within the context of another process, potentially leading to unauthorized actions or evasion of security controls. According to the MITRE ATT&CK framework, this technique is categorized under "Process Injection" (T1055).

This rule helps detect and audit suspicious usage of `NtMapViewOfSection`, providing an early warning for potential malicious activities involving process injection.

- [MITRE ATT&CK: Process Injection](https://attack.mitre.org/techniques/T1055/)

## Detection Logic
- Monitors `DeviceEvents` for events where:
  - The `ActionType` includes "NtMapViewOfSectionRemoteApiCall".
  - The `FileName` is not "firefox.exe".
  - The `FileName` is not "MicrosoftEdgeCP.exe".

## Tags
- Process Injection
- NtMapViewOfSection
- Remote API Call
- MITRE ATT&CK T1055
- Suspicious Activity

## Search Query
```kql
DeviceEvents 
| where ActionType has_any('NtMapViewOfSectionRemoteApiCall')
| where FileName != "firefox.exe" and FileName != "MicrosoftEdgeCP.exe"
```
