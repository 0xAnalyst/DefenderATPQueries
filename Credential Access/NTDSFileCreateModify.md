# Rule : NTDS.DIT File Creation or Copy Activity

## Description
This detection identifies instances where the **NTDS.dit** file — the Active Directory database file containing credential and identity data — is **created or copied** on a Windows system.  
Such activity is highly suspicious, as attackers often attempt to copy or extract this file to obtain password hashes and authentication data from a domain controller.  

Legitimate access to `NTDS.dit` is typically restricted to the **Active Directory process (LSASS)** and backup utilities running under **SYSTEM context**. Therefore, detection of file creation or copy events targeting this file outside expected system paths may indicate credential theft or **Active Directory database exfiltration** attempts.

- Reference: [MITRE ATT&CK – T1003.003: OS Credential Dumping: NTDS](https://attack.mitre.org/techniques/T1003/003/)

## Detection Logic
- Monitors **DeviceFileEvents** for actions related to `ntds.dit`.
- Flags when a file named `ntds.dit` is **created** or **copied**.
- Common sources of this behavior in attacks include:
  - Use of tools such as **ntdsutil**, **esentutl**, or **copy** commands.
  - Shadow copy or Volume Snapshot Service (VSS) abuse to access the file.

## Tags
- MITRE ATT&CK: T1003.003 (OS Credential Dumping: NTDS)
- Category: Credential Access  
- Platform: Windows  
- Data Source: DeviceFileEvents  
- Severity: High  

## Search Query
```kql
DeviceFileEvents
| where FileName =~ "ntds.dit"
| where ActionType in ("FileCreated","FileCopied")
