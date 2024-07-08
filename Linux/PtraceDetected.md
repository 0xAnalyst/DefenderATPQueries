#Detection of Ptrace System Call (PTraceDetected)

## Description
This detection rule identifies the usage of the `ptrace` system call on Linux systems. The `ptrace` system call is used by debuggers and other programs to observe and control the execution of another process. While `ptrace` is a legitimate tool, it can also be misused by attackers for various malicious activities such as process injection, code execution, and obtaining sensitive information from other processes.

This rule monitors for events where the `ptrace` system call is detected. Unauthorized use of `ptrace` can indicate attempts to hijack or manipulate running processes.

- [MITRE ATT&CK Technique T1055.008: Process Injection - Ptrace System Calls](https://attack.mitre.org/techniques/T1055/008/)

## Detection Logic
- Monitors `DeviceEvents` for events where:
  - The `ActionType` is "PTraceDetected".

## Tags
- Process Injection
- ptrace
- Linux Security
- Suspicious Activity
- MITRE T1055.008

## Search Query
```kql
DeviceEvents 
| where ActionType == "PTraceDetected"

