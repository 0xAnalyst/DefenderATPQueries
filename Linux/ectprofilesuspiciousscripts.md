# Rule: Detection of Suspicious Shell Scripts in Profile Directory

## Description
This detection rule identifies suspicious shell scripts located in the `/etc/profile.d/` directory on Linux systems. Shell scripts in this directory are typically used to configure the environment for all users on the system. The presence of unusual or unauthorized shell scripts may indicate persistence attempts by attackers, aiming to execute malicious code during user logins or system startup.

This rule monitors for the creation or modification of shell scripts in the `/etc/profile.d/` directory, excluding scripts initiated by the `platform-python3.6` process, which is generally considered benign.

- [Sigma Rule: Suspicious Shell Script in Profile Directory](https://github.com/SigmaHQ/sigma/blob/0bb6f0c0d75ae3e1c37f9ab77d68f20cdb32ecd3/rules/linux/file_event/file_event_lnx_susp_shell_script_under_profile_directory.yml)

## Detection Logic
- Monitors `DeviceFileEvents` for events where:
  - The `FileName` ends with ".sh", ".zsh", or ".csh".
  - The `InitiatingProcessFileName` is not "platform-python3.6".
  - The `FolderPath` contains "/etc/profile.d/".

## Tags
- File Events
- Persistence
- Shell Script
- Profile Directory
- Linux Security
- Suspicious Activity

## Search Query
```kql
DeviceFileEvents
| where FileName endswith ".sh" or FileName endswith ".zsh" or FileName endswith ".
