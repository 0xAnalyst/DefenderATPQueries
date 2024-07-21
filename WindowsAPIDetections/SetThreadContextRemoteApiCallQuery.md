# Rule : Detection of SetThreadContext Remote API Call

## Description
This detection rule identifies suspicious usage of the `SetThreadContext` function for remote API calls. The `SetThreadContext` function is used to modify the context of a specified thread, which can be leveraged by malicious actors to inject code into another process's address space. This technique allows attackers to execute arbitrary code within the context of another process, potentially leading to unauthorized actions or evasion of security controls. According to the MITRE ATT&CK framework, this technique falls under "Process Injection: Thread Execution Hijacking" (T1055.003).

This rule helps detect and audit suspicious usage of `SetThreadContext`, providing an early warning for potential malicious activities involving process injection.

- [MITRE ATT&CK: Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003/)

## Detection Logic
- Monitors `DeviceEvents` for events where:
  - The `ActionType` is "SetThreadContextRemoteApiCall".

## Tags
- Process Injection
- SetThreadContext
- Remote API Call
- MITRE ATT&CK T1055.003
- Suspicious Activity

## Search Query
```kql
DeviceEvents
| where ActionType == "SetThreadContextRemoteApiCall"
```
