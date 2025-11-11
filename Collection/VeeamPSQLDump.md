# Rule : Credential Dump from Veeam PostgreSQL Database

## Description
Detects suspicious use of PostgreSQL client tools or SQL queries that extract credentials or configuration data from backup product databases (e.g., Veeam). Attackers may query Veeam's PostgreSQL database to obtain stored credentials for targets or backup repositories.

- **Source:** The DFIR Report — From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira (Aug 05, 2025)

## Detection Logic
- Alert on `psql.exe` or `psql` commandline usage, especially with queries referencing tables that contain credentials or configuration (e.g., `credentials`, `backup`, `repository`).
- Correlate with local database service connections or dumps to files.
- Flag when database queries are run by non-database admins or from atypical hosts.

## Tags
- Credential Access  
- Data Exfiltration  
- MITRE ATT&CK: T1005 (Data from Local System), T1537 (Transfer Data to Cloud Account)

## Search Query
```kql
DeviceProcessEvents
| where FileName =~ "psql.exe" or ProcessCommandLine contains "psql "
| where ProcessCommandLine contains "Veeam" or ProcessCommandLine has_all ("SELECT","username","credentials") or ProcessCommandLine contains "COPY"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, ReportId
```
