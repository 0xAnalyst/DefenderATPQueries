# Rule: Detection of Suspicious File Creation Related to TripleCrosse eBPF Backdoor

## Description
This detection rule identifies the creation of suspicious files named "ebpfbackdoor" or "rootlog" on Linux systems. These files are associated with malicious activities, such as the installation of rootkits or backdoors. The creation of such files can indicate an attempt to establish persistence or hide unauthorized activities on the system.

This rule monitors for the creation of files with names indicative of known malicious tools, focusing on files that are not typically present in legitimate environments.

- [Sigma Rule: TripleCross Rootkit Lock File](https://github.com/SigmaHQ/sigma/blob/0bb6f0c0d75ae3e1c37f9ab77d68f20cdb32ecd3/rules/linux/file_event/file_event_lnx_triple_cross_rootkit_lock_file.yml)
- [Sigma Rule: TripleCross Rootkit Persistence](https://github.com/SigmaHQ/sigma/blob/0bb6f0c0d75ae3e1c37f9ab77d68f20cdb32ecd3/rules/linux/file_event/file_event_lnx_triple_cross_rootkit_persistence.yml)

## Detection Logic
- Monitors `DeviceFileEvents` for events where:
  - The `ActionType` is "FileCreated".
  - The `FileName` contains "ebpfbackdoor" or "rootlog".

## Tags
- File Events
- Persistence
- Rootkit
- eBPF Backdoor
- Linux Security
- Suspicious Activity

## Search Query
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName contains "ebpfbackdoor" or FileName contains "rootlog"
