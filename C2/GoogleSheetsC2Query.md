# Rule Documentation: Suspicious Non-Browser Access to Google APIs by Rare Processes on Windows

## Description
This detection rule identifies suspicious network connections to key Google API endpoints—such as `drive.googleapis.com`, `oauth2.googleapis.com`, `sheets.googleapis.com`, and `www.googleapis.com`—that are initiated by processes other than standard web browsers or legitimate Google Drive File Stream (`googledrivefs.exe`). Attackers may use custom or rarely seen processes to interact with these endpoints for data exfiltration, command and control, or other malicious activities.

To enhance detection accuracy, the rule invokes file profiling on the initiating process using its SHA1 hash and flags events where the process has a low global prevalence (less than 100). The rule also ensures that the detected activity originates from Windows devices by joining with the `DeviceInfo` table.

## Detection Logic
- **Google API Endpoints:**  
  Monitor network events where the `RemoteUrl` contains any of the following:
  - `drive.googleapis.com`
  - `oauth2.googleapis.com`
  - `sheets.googleapis.com`
  - `www.googleapis.com`

- **Non-Browser Filter:**  
  Exclude events where the initiating process is one of the common web browsers or the legitimate Google Drive File Stream:
  - `"chrome.exe"`, `"firefox.exe"`, `"msedge.exe"`, `"edge.exe"`, `"googledrivefs.exe"`

- **Rare Process Check:**  
  Use file profiling (based on `InitiatingProcessSHA1`) to flag processes with a global prevalence of less than 100.

- **Windows Platform Verification:**  
  Join with the `DeviceInfo` table to ensure the event originates from a Windows client (where `OSPlatform` contains "windows").

## Tags
- Network Connection
- Google API
- Non-Browser Access
- Rare Process
- Data Exfiltration
- Windows Security
- Suspicious Activity

## Search Query
```kql
DeviceNetworkEvents
| where RemoteUrl has_any( @"drive.googleapis.com", @"oauth2.googleapis.com", "sheets.googleapis.com", "www.googleapis.com")
| where InitiatingProcessFileName !in ("chrome.exe", "firefox.exe", "msedge.exe", "edge.exe", "googledrivefs.exe")
| invoke FileProfile(InitiatingProcessSHA1)
| where GlobalPrevalence < 100 
| join kind=inner (
    DeviceInfo
    | project DeviceId, OSPlatform
) on DeviceId
| where OSPlatform contains "windows"
```
## Notes
This might be generating false positive and the query needs fine tunning from you
