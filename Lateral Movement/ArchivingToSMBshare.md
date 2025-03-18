# Rule : Detection of 7-Zip Archiving to SMB Admin Shares

## Description
This detection rule identifies suspicious usage of **7-Zip** (`7z.exe`, `7za.exe`, `7zr.exe`) to interact with administrative SMB shares such as **C$**, **Admin$**, or **IPC$**. Attackers may use **7-Zip** to compress and archive files before exfiltrating data via network shares. This technique is commonly associated with **lateral movement** and **data exfiltration** in targeted attacks.

In many environments, legitimate use of **7-Zip** does not involve direct interaction with administrative network shares. Therefore, monitoring this behavior can help detect potential misuse by adversaries attempting to stage or exfiltrate data.

- [Splunk Research: 7-Zip Archive Created in SMB Share](https://research.splunk.com/endpoint/01d29b48-ff6f-11eb-b81e-acde48001123/)

## Detection Logic
- **Monitors `DeviceProcessEvents`** where:
  - The `FileName` or `ProcessVersionInfoOriginalFileName` matches:
    - `"7z.exe"`
    - `"7za.exe"`
    - `"7zr.exe"`
  - The `ProcessCommandLine` contains:
    - `"\\C$\\"` (Admin Share)
    - `"\\Admin$\\"` (Administrative Access)
    - `"\\IPC$\\"` (Inter-Process Communication Share)

## Tags
- Data Exfiltration
- Lateral Movement
- SMB Share Monitoring
- Suspicious File Archiving
- Windows Security

## Search Query
```kql
DeviceProcessEvents
| where FileName in ("7z.exe", "7za.exe", "7zr.exe") 
   or ProcessVersionInfoOriginalFileName in ("7z.exe", "7za.exe", "7zr.exe")
| where ProcessCommandLine has_any ("\\C$\\", "\\Admin$\\", "\\IPC$\\")
```
