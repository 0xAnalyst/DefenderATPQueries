# Rule Documentation: RustDesk Remote Access Tool Installation for Persistence

## Description
Detects installation or use of remote access tools like RustDesk on servers or privileged endpoints where such tools are not authorized. Attackers often install legitimate remote tools to maintain remote access and bypass controls.

- **Source:** The DFIR Report — From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira (Aug 05, 2025)

## Detection Logic
- Monitor for installer execution of `rustdesk.exe`/`rustdesk-service` or creation of persistent services related to RustDesk.
- Alert when remote access tools are installed on domain controllers, file servers, or admin workstations.
- Correlate with SSH tunneling, scheduled tasks, or service creation.

## Tags
- Persistence  
- Remote Access  
- MITRE ATT&CK: T1219 (Remote Access Tools), T1543 (Create or Modify System Process)

## Search Query
```kql
DeviceProcessEvents
| where FileName has_any ("rustdesk.exe","rustdesk-service.exe","rustdesk")
| join kind=leftouter (
    DeviceImageLoadEvents
    | where FolderPath has "Program Files" or FolderPath has "ProgramData"
) on DeviceId
| project Timestamp, DeviceName, FileName, ProcessCommandLine, FolderPath, ReportId
```
