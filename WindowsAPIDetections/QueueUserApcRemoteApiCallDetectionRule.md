# Rule : Detection of QueueUserAPC Remote API Call

## Description
This detection rule identifies suspicious usage of the `QueueUserAPC` function for remote API calls. The `QueueUserAPC` function allows a program to specify a function to be called asynchronously in the context of a specified thread. While this is a legitimate function used by many applications, it can be exploited by malicious actors to execute arbitrary code in the context of another process, facilitating process injection and potentially leading to unauthorized actions or evasion of security controls. According to the MITRE ATT&CK framework, this technique is categorized under "Process Injection: Asynchronous Procedure Call (APC) Injection" (T1055.004).

This rule helps detect and audit suspicious usage of `QueueUserAPC`, providing an early warning for potential malicious activities involving process injection.

- [MITRE ATT&CK: Asynchronous Procedure Call (APC) Injection](https://attack.mitre.org/techniques/T1055/004/)

## Detection Logic
- Monitors `DeviceEvents` for events where:
  - The `ActionType` is "QueueUserApcRemoteApiCall".
  - The `InitiatingProcessCommandLine` is not `"svchost.exe -k netsvcs -p -s ShellHWDetection"`.
  - The `InitiatingProcessVersionInfoProductName` is not "Microsoft Edge Installer".
  - The `ProcessCommandLine` is not `"svchost.exe -k netsvcs -p -s Winmgmt"`.

## Tags
- Process Injection
- APC Injection
- QueueUserAPC
- Remote API Call
- MITRE ATT&CK T1055.004
- Suspicious Activity

## Search Query
```kql
DeviceEvents
| where ActionType == "QueueUserApcRemoteApiCall"
| where InitiatingProcessCommandLine != "svchost.exe -k netsvcs -p -s ShellHWDetection"
| where InitiatingProcessVersionInfoProductName != "Microsoft Edge Installer"
| where ProcessCommandLine != "svchost.exe -k netsvcs -p -s Winmgmt"
```
