# Rule: Unexpected MSI Installation from User Directory Spawning consent.exe

## Description
This rule detects suspicious **MSI installer executions** launched from **user-writable directories** such as `Downloads`, `Desktop`, `AppData`, or `ProgramData`, that subsequently spawn the **`consent.exe`** process.

This behavior is commonly associated with **malicious MSI-based loaders** (e.g., *Bumblebee*) that abuse Windows’ User Account Control (UAC) mechanisms and DLL side-loading for stealth execution and persistence.

In *The DFIR Report* case study *“From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira”* (August 2025), a trojanized installer (`ManageEngine-OpManager.msi`) executed legitimate software while side-loading a malicious `msimg32.dll` via `consent.exe`. This detection aims to identify similar initial access and execution behaviors.

- **Source:** [The DFIR Report — From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira](https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira/)

## Detection Logic
- Monitor process creation events where `msiexec.exe` is executed from **non-standard user paths**, such as:
  - `C:\Users\*\Downloads\*`
  - `C:\Users\*\Desktop\*`
  - `C:\ProgramData\*`
  - `C:\Users\*\AppData\*`
and  spawns **`consent.exe`**, which is uncommon for legitimate installers.
- Flag unsigned or unknown MSI installers that perform secondary executions or DLL loads (`msimg32.dll` or similar).

## Tags
- Initial Access  
- Execution  
- Defense Evasion  
- MSI Abuse  
- DLL Side-Loading  
- Bumblebee Loader  
- MITRE ATT&CK:  
  - **T1204.002** – User Execution: Malicious File  
  - **T1574.002** – Hijack Execution Flow: DLL Side-Loading  

## Search Query
```kql
// Detect MSI installers launched from user-writable paths spawning consent.exe
DeviceProcessEvents
| where FileName =~ "msiexec.exe"
| where InitiatingProcessFolderPath has_any (
    "\\Users\\", "\\ProgramData\\", "\\Desktop\\", "\\Downloads\\", "\\AppData\\"
)
| where InitiatingProcessCommandLine has_any (".msi", "/i", "/qn")
| join kind=inner (
    DeviceProcessEvents
    | where FileName =~ "consent.exe"
) on DeviceId, InitiatingProcessId
| project Timestamp, DeviceName,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          FileName, FolderPath, ReportId
