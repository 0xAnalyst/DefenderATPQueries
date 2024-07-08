# Detection of Unauthorized Creation of Files in /etc/sudoers.d/

## Description
This detection rule identifies attempts to create files in the `/etc/sudoers.d/` directory on Linux systems. The `/etc/sudoers.d/` directory is used to include additional sudoers configuration files. Unauthorized creation of files in this directory could indicate an attempt to escalate privileges or gain unauthorized access by adding malicious sudoers configurations.

This rule monitors for file creation events in the `/etc/sudoers.d/` directory. Such activity is not typically seen during standard operations and may indicate malicious intent to modify sudo privileges.

- [Sigma Rule: Persistence via Sudoers File](https://github.com/SigmaHQ/sigma/blob/0bb6f0c0d75ae3e1c37f9ab77d68f20cdb32ecd3/rules/linux/file_event/file_event_lnx_persistence_sudoers_files.yml)

## Detection Logic
- Monitors `DeviceFileEvents` for events where:
  - The `ActionType` is "FileCreated", and
  - The `FolderPath` contains `/etc/sudoers.d/`.

## Tags
- File Events
- Privilege Escalation
- sudoers
- Linux Security
- Suspicious Activity

## Search Query
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath contains "/etc/sudoers.d/"
