# Rule : Data Staging in `C:\ProgramData` followed by Outbound File Transfer Activity "filezilla,psftp,winscp"

## Description
This detection rule identifies potential **data staging followed by exfiltration** from compromised systems. It correlates file-write events under `C:\ProgramData\` (where adversaries often stage reconnaissance results or sensitive data) with **subsequent outbound network connections** to public IP addresses using FTP/SFTP clients such as **FileZilla**, **WinSCP**, or **psftp**.

Attackers commonly:
1. Run discovery commands (`net view`, `Get-SmbShare`, `Get-ADComputer`, etc.)  
2. Store results in `C:\ProgramData\shares.txt` or similar `.txt` files.  
3. Shortly afterward, use an SFTP/FTP client to transfer these staged files externally.  

This rule detects that pattern within a **5-hour correlation window** between the file staging and outbound data transfer.

## Detection Logic
- **Monitors:**  
  - File writes to `C:\ProgramData\shares.txt` and other `.txt` files (excluding legitimate Defender ATP download directory).  
  - Outbound network events from known SFTP/FTP clients (`filezilla.exe`, `psftp.exe`, `sftp.exe`, `winscp.exe`, `pscp.exe`, `lftp.exe`).  
- **Correlates:** file-write and outbound events occurring on the same device (`DeviceId`) within a **5-hour window**.  
- **Summarizes:**  
  - Earliest file write (`first_write`)  
  - Latest network event (`last_network_activity`)  
  - Count of total connections (`connections`)  
  - Distinct external destinations (`distinct_remote_ips`)  
- **Flags:** hosts where outbound connections to public IPs followed file staging activity.

## Tags
- Exfiltration  
- Collection  
- Data Staging  
- File Transfer  
- MITRE ATT&CK:  
  - **T1005** – Data from Local System  
  - **T1041** – Exfiltration Over C2 Channel  
  - **T1537** – Transfer Data to Cloud Account  

## Search Query
```kql
// Correlate staging with outbound connections (SFTP/FTP/FileZilla) in next 5 hours
let fileWrites = DeviceFileEvents
| where FolderPath has_cs "\\ProgramData\\" 
  and FolderPath !startswith @"C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\"
| where FileName == "shares.txt" or FileName endswith ".txt"
| project DeviceId, DeviceName, FileName, FilePath=FolderPath, FileWriteTime=Timestamp, ReportId;
let outbounds = DeviceNetworkEvents
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in ("filezilla.exe","psftp.exe","sftp.exe","winscp.exe","pscp.exe","lftp.exe")
| project DeviceId, RemoteIP, RemoteUrl, RemotePort, NetTimestamp=Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine;
fileWrites
| join kind=inner (outbounds) on DeviceId
| where NetTimestamp between (FileWriteTime .. FileWriteTime + 5h)
| summarize first_write=min(FileWriteTime), last_network_activity=max(NetTimestamp), connections=count(), distinct_remote_ips=dcount(RemoteIP)
   by DeviceId, DeviceName, FileName, FilePath
| where connections > 0
| project first_write, last_network_activity, DeviceName, FileName, connections, distinct_remote_ips
