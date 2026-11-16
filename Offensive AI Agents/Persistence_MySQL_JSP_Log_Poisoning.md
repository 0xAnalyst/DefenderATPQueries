# Rule : MySQL General-Log Poisoning via Process-Visible SQL Strings

## Description
Detects SQL commands that redirect the MySQL general log to a file (`SET GLOBAL general_log`, `general_log_file`) or `SELECT` statements containing JSP tags (`<%`). This is the log-poisoning technique ARTEX used to try to write a JSP webshell through the database.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-008
- **Severity:** High (initial suggestion; tune before alerting)
- **Provenance:** Report-documented behavior

## Detection Logic
- Searches `DeviceProcessEvents` command lines for `general_log_file`, `SET GLOBAL general_log`, or `SELECT` combined with `<%`.

## Relevant Tables
- `DeviceProcessEvents`

## Tags
- Agentic Offense
- ARTEX
- Persistence
- Webshell
- SQL Abuse
- MITRE ATT&CK: T1505.003 (Server Software Component: Web Shell)

## Search Query
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine contains "general_log_file" or ProcessCommandLine contains "SET GLOBAL general_log" or (ProcessCommandLine contains "SELECT" and ProcessCommandLine contains "<%")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## False Positive Tuning
- DB troubleshooting.
- Exclude DBA troubleshooting sessions that toggle the general log.

## Triage Steps
1. Check where `general_log_file` was pointed — a web root is a strong indicator.
2. Review `DeviceFileEvents` for a resulting `.jsp` file (OAI-007).

## Note
SQL strings visible in endpoint commandline only, not SQL protocol contents. Thresholds are starting points, not validated defaults — run as a hunt first.
