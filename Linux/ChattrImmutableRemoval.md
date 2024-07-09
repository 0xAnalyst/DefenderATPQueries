# Rule : Immutable Attribute Removal Detection

## Description
Detects the use of the `chattr` command with the `-i` flag, which is used to remove the immutable attribute from files on Linux systems. The immutable attribute prevents a file from being modified or deleted, and its removal could indicate an attempt to tamper with critical system files or logs.

- Source: [Sigma rule for detecting immutable attribute removal](https://github.com/SigmaHQ/sigma/blob/0bb6f0c0d75ae3e1c37f9ab77d68f20cdb32ecd3/rules/linux/process_creation/proc_creation_lnx_chattr_immutable_removal.yml)

## Detection Logic
- Monitors process events where the `chattr` command is used with the `-i` flag, indicating an attempt to remove the immutable attribute from a file.

## Tags
- Immutable Attribute
- File Tampering
- Process Events
- Linux

## Search Query
```kql
DeviceProcessEvents
| where ProcessCommandLine has_all ("chattr", "-i")
