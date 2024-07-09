# Rule : Sensitive File Copy to /tmp Directory

## Description
Detects attempts to copy sensitive system files, such as `shadow` and `passwd`, to the `/tmp` directory using the `cp` command. These files contain critical information about user accounts and passwords, and copying them to a temporary directory may indicate malicious intent to exfiltrate or manipulate sensitive data.

- Source: [Sigma rule for detecting copying of sensitive files to /tmp](https://github.com/SigmaHQ/sigma/blob/0bb6f0c0d75ae3e1c37f9ab77d68f20cdb32ecd3/rules/linux/process_creation/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml)

## Detection Logic
- Monitors process events where the executed file name is `cp`.
- Filters for instances where the process command line contains `/tmp` and includes either `shadow` or `passwd`, indicating an attempt to copy these sensitive files to the `/tmp` directory.

## Tags
- Sensitive File Copy
- Shadow File
- Passwd File
- Process Events
- Linux

## Search Query
```kql
DeviceProcessEvents
| where FileName == "cp" and ProcessCommandLine contains "/tmp" and ProcessCommandLine has_any ("shadow", "passwd")
