# Rule : Detection of Unsigned Executable Launches from User Directories

## Description
This detection rule identifies instances where unsigned or suspiciously signed executable files (`.exe`) are launched from common user directories—such as `\Users\`, `\Downloads\`, `\AppData\`, and `\Temp\`—by typical user-facing applications like **Explorer**, **Google Chrome**, or **Microsoft Edge**. Such behavior is often indicative of malicious activity, where attackers trick users into downloading and executing harmful payloads through familiar applications.

The relevance of this detection is underscored by incidents like the **Fake Zoom Installer** campaign, where users were deceived into downloading a malicious Zoom installer. This installer executed additional payloads, leading to severe compromises, including ransomware deployment. Monitoring for unsigned executables originating from user directories can help in early detection of such deceptive tactics.

- [Fake Zoom Ends in BlackSuit Ransomware](https://thedfirreport.com/2025/03/31/fake-zoom-ends-in-blacksuit-ransomware/)

## Detection Logic
- **Monitored Directories:**
  - `\Users\`
  - `\Downloads\`
  - `\AppData\`
  - `\Temp\`

- **Signature Status:**
  - `Unknown`
  - `Unsigned`
  - `Invalid`

- **File Type:**
  - Files ending with `.exe`

- **Exclusions:**
  - Processes associated with known legitimate software, such as:
    - **Telegram** (`Telegram FZ-LLC`)
    - **Zoom**

- **Initiating Processes:**
  - `explorer.exe`
  - `chrome.exe`
  - `msedge.exe`

## Tags
- Unsigned Executables
- User Directory Execution
- Initial Access
- Malware Delivery
- Windows Security
- Fake Installer Detection

## Search Query
```kql
DeviceProcessEvents
| where FolderPath has_any ("\\Users\\", "\\Downloads\\", "\\AppData\\", "\\Temp\\")
| where InitiatingProcessSignatureStatus in ("Unknown", "Unsigned", "Invalid")
| where FileName endswith ".exe"
| where ProcessVersionInfoCompanyName != "Telegram FZ-LLC"
| where ProcessVersionInfoProductName != "Zoom"
| where InitiatingProcessVersionInfoFileDescription != "Google Chrome"
| where InitiatingProcessFileName in~ ("explorer.exe", "chrome.exe", "msedge.exe")
```
## Notes
Exclude and fine tune in your enviroment
