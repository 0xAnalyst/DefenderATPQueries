# Rule : Detection of Suspicious File Events Involving DevTunnels

## Description
This detection rule monitors for suspicious file operations involving folders named "DevTunnels." DevTunnels are a feature used in Visual Studio for creating secure tunnels for remote connections, commonly utilized for remote debugging or development. Any unusual file activities within this folder could signal potential misuse or unauthorized operations by malicious actors attempting to establish or maintain persistence on the system.

This rule specifically excludes known legitimate software, such as Dell Display Manager 2, from triggering false positives. Monitoring DevTunnels for unexpected file activity can help detect potential threat actors utilizing this feature for lateral movement or remote access.

- [Related SigmaHQ Rule for DevTunnels Monitoring](https://github.com/SigmaHQ/sigma/blob/ab2fb3642611988012a1ee79b056e2f3068059aa/rules/windows/dns_query/dns_query_win_devtunnels_communication.yml)

## Detection Logic
- Monitors `DeviceFileEvents` for events where:
  - The `FolderPath` contains "DevTunnels", and
  - Excludes legitimate software such as Dell Display Manager 2.

## Tags
- File Events
- DevTunnels Monitoring
- Suspicious File Access
- Visual Studio Security
- Threat Detection

## Search Query
```kql
DeviceFileEvents
| where FolderPath has "DevTunnels" 
 //exclude Dell Display Manager  | where InitiatingProcessFileName != "DellDisplayManager.exe"
```
