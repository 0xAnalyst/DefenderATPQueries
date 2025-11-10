# Rule : NTDS.dit Dump via wbadmin.exe Abuse

## Description
Detects abuse of Windows Backup (`wbadmin.exe`) to export sensitive Active Directory artifacts such as `NTDS.dit`, `SYSTEM`, and `SECURITY` hives. Attackers may use `wbadmin start backup` with `-include` flags targeting these files to extract account hashes and secrets.

- **Source:** The DFIR Report — From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira (Aug 05, 2025)

## Detection Logic
- Alert on `wbadmin.exe` or backup tools invoked with `-include` parameters referencing `C:\Windows\NTDS\ntds.dit` or `C:\Windows\System32\config\SYSTEM` or `SECURITY`.
- Correlate backup target paths that point to remote shares or user-writable locations.
- Flag when such operations are initiated by non-admin or unexpected service accounts.

## Tags
- Credential Access  
- Discovery  
- MITRE ATT&CK: T1003 (OS Credential Dumping)

## Search Query
```kql
DeviceProcessEvents
| where FileName =~ "wbadmin.exe" or ProcessCommandLine contains "wbadmin"
| where ProcessCommandLine contains "ntds.dit" or ProcessCommandLine contains "config\\SYSTEM" or ProcessCommandLine contains "config\\SECURITY"
| project Timestamp,DeviceId, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, ReportId
```
