# Rule : Sudoers File Access Detection

## Description
Detects attempts to read the `sudoers` file using common text viewing and searching commands. The `sudoers` file controls user privileges and its unauthorized access may indicate attempts to gain elevated privileges or gather sensitive information about system configurations.

- Source: [Sigma rule for detecting access to sudoers file](https://github.com/SigmaHQ/sigma/blob/0bb6f0c0d75ae3e1c37f9ab77d68f20cdb32ecd3/rules/linux/process_creation/proc_creation_lnx_cat_sudoers.yml)

## Detection Logic
- Monitors process events where the executed file name is one of the following text viewing and searching commands: `cat`, `grep`, `head`, `tail`, `more`.
- Filters for instances where the process command line contains the term `sudoers`, indicating an attempt to access the sudoers file.

## Tags
- Sudoers File Access
- Privilege Escalation
- Process Events
- Linux

## Search Query
```kql
DeviceProcessEvents
| where FileName in ('cat', 'grep', 'head', 'tail', 'more')
| where ProcessCommandLine contains "sudoers"
