# Rule: Suspicious CLFS Driver Load

## Description
This detection rule identifies suspicious loading of the CLFS driver, which may indicate an attempt to inject or manipulate kernel modules for malicious purposes. The CLFS (Common Log File System) driver, normally located in a trusted system directory, is a critical component for managing log files in Windows. When this driver is loaded from an unexpected location or in an unusual context, it can be an indicator of kernel-level compromise or persistence mechanisms employed by adversaries.

Monitoring image load events for the CLFS driver can provide early detection of such exploitation attempts, enabling rapid investigation and remediation.

- [Sigma Rule: Image Load CLFS Load](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_clfs_load/)  

## Detection Logic
- Monitors `DeviceImageLoadEvents` for events where the loaded image corresponds to the CLFS driver (e.g., `clfs.sys`).
- Flags events that deviate from normal, trusted behavior for the CLFS driver load (e.g., loading from non-standard directories).

## Tags
- Windows Security
- Image Load Events
- Suspicious Driver Load
- Kernel Module Manipulation
- Persistence
- CLFS
-  CVE-2024-38196

## Search Query
```kql
DeviceImageLoadEvents
| where FileName endswith "clfs.sys"
| where not( FolderPath startswith @"C:\Windows\System32\drivers\" )
```
## Exclusions
you might need to exclude legit path's in your enviroment 
