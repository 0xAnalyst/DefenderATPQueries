# Rule Documentation: Detection of Suspicious MSI and DLL Activity Associated with Latrodectus Malware

## Description
This detection rule identifies suspicious file and process activities that could be indicative of Latrodectus malware or similar threats. The query monitors for specific file paths, particularly MSI files and the `aclui.dll`, often used in malicious contexts, in combination with `msiexec` or `rundll32` processes. Latrodectus malware, as described in recent analyses, leverages these files and processes to execute payloads and achieve persistence on infected systems.

Latrodectus is a sophisticated malware family known for its ability to evade detection and deliver various payloads, including information stealers and ransomware. This rule is designed to detect the early stages of Latrodectus infection, focusing on suspicious file creations and process executions that are not typically associated with legitimate software installations or updates.

- [Latrodectus Malware Analysis](https://blog.krakz.fr/articles/latrodectus/)

## Detection Logic
- Monitors `DeviceFileEvents` for events where:
  - The `FolderPath` contains any of the following suspicious files:
    - `"aclui.dll"`,
    - `"Roaming\\capisp"`,
    - `"temp\\vpn.msi"`,
    - `"neuro.msi"`,
    - `"bst.msi"`,
    - `"aes256.msi"`,
    - `"neo.msi"`,
    - `"bim.msi"`,
    - `"WSC.msi"`.
  - The `InitiatingProcessCommandLine` includes `"msiexec"` or `"rundll32"`.

## Tags
- Latrodectus Malware
- Suspicious MSI Activity
- DLL Hijacking
- Process Execution
- MITRE ATT&CK T1059 (Command and Scripting Interpreter)
- Persistence
- Suspicious Activity

## Search Query
```kql
DeviceFileEvents
| where FolderPath has_any ("aclui.dll", "Roaming\\capisp", "temp\\vpn.msi", "neuro.msi", "bst.msi","aes256.msi","neo.msi","bim.msi","WSC.msi") 
| where InitiatingProcessCommandLine has_any("msiexec", "rundll32")
