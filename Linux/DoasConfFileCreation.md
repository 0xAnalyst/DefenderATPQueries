# Rule Documentation: Detection of Unauthorized Creation of doas.conf File

## Description
This detection rule identifies attempts to create the `doas.conf` file on Linux systems. The `doas.conf` file is used by the `doas` command to provide a minimalistic alternative to `sudo` for privilege escalation. Unauthorized creation of this file could indicate malicious activity, such as an attempt to configure `doas` settings to gain elevated privileges.

This rule monitors for the creation of the `doas.conf` file, which is not typically created during standard operations. The presence of this file may indicate an attempt to set up unauthorized privilege escalation on the system.

- [Detection Rule: Creation of Suspicious doas.conf File](https://research.splunk.com/endpoint/f6343e86-6e09-11ec-9376-acde48001122/)

## Detection Logic
- Monitors `DeviceFileEvents` for events where:
  - The `ActionType` is "FileCreated", and
  - The `FileName` ends with "doas.conf".

## Tags
- File Events
- Privilege Escalation
- doas
- Linux Security
- Suspicious Activity

## Search Query
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith "doas.conf"
