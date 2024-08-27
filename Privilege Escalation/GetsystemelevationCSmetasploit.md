# Rule : Detection of cmd.exe Echo Pipe Commands

## Description
This detection rule identifies suspicious usage of the `cmd.exe` process executing commands that involve `echo` combined with a pipe (`|`). Attackers often use such techniques during post-exploitation to gain elevated privileges or to manipulate data streams on compromised systems. This method is associated with various offensive security activities, including the well-known `getsystem` technique for privilege escalation.

Monitoring command-line activities that combine `echo` and piping is important for detecting attempts to modify or redirect output, potentially aiding in data exfiltration or system tampering.

- [Red Canary: Detecting Getsystem and Offensive Security Techniques](https://redcanary.com/blog/threat-detection/getsystem-offsec/)

## Detection Logic
- Monitors `DeviceProcessEvents` for events where:
  - The `FileName` is `cmd.exe`, and
  - The `ProcessCommandLine` contains both `"echo"` and `"pipe"` operations.

## Tags
- cmd.exe Monitoring
- Privilege Escalation
- Offensive Security Tools
- Suspicious Command-Line Activity
- Threat Detection

## Search Query
```kql
DeviceProcessEvents
| where FileName == @"cmd.exe" and ProcessCommandLine has_all("echo", "pipe")
