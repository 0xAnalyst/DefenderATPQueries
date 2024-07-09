# Rule : Capability Discovery via getcap

## Description
Detects the use of the `getcap` command, which is used to query the capabilities of executables on Linux systems. Capabilities can grant elevated privileges to executables, and discovering these capabilities can be part of an attacker's reconnaissance phase. This detection specifically excludes instances where `getcap` is run by the `vmtoolsd` service.

- Source: [Sigma rule for detecting capability discovery](https://github.com/SigmaHQ/sigma/blob/0bb6f0c0d75ae3e1c37f9ab77d68f20cdb32ecd3/rules/linux/process_creation/proc_creation_lnx_capa_discovery.yml)

## Detection Logic
- Monitors for process events where the executed file name is `getcap`.
- Excludes events where the initiating process folder path is `/usr/bin/vmtoolsd`, which is typically a legitimate use case associated with VMware Tools.

## Tags
- Capability Discovery
- getcap
- Process Events
- Linux

## Search Query
```kql
DeviceProcessEvents
| where FileName == "getcap" and InitiatingProcessFolderPath != "/usr/bin/vmtoolsd"
