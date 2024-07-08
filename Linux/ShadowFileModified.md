# Detection of Unauthorized Renaming of /etc/shadow

## Description
This detection rule identifies attempts to rename the `/etc/shadow` file on Linux systems. The `/etc/shadow` file contains hashed passwords for user accounts and should never be renamed during normal operations. Unauthorized renaming of this file could indicate malicious activity, such as an attempt to hide unauthorized changes to user passwords.

This rule monitors for Linux shadow file modifications. These modifications are indicative of a potential password change or user addition event. Threat actors may attempt to create new users or change the password of a user account to maintain access to a system.

- [Elastic Detection Rule on Persistence via User Password Change](https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_user_password_change.toml)

## Detection Logic
- Monitors `DeviceFileEvents` for events where:
  - The `ActionType` contains "FileRenamed", and
  - The `FileName` is `/etc/shadow`.

## Tags
- File Events
- Persistence
- User Password Change
- /etc/shadow
- Linux Security
- Suspicious Activity

## Search Query
```kql
DeviceFileEvents
| where ActionType contains "FileRenamed"
| where FileName == @"/etc/shadow"
