# Rule : Web Executable File Written by Server and Database Process

## Description
Detects `.jsp`, `.jspx`, `.aspx`, `.ashx` and `.php` files written by web-server or database processes, or written into web roots. The report describes ARTEX attempting SQL-to-JSP webshell placement; a database or web process writing a server-side script file is a classic webshell drop.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-007
- **Severity:** High (initial suggestion; tune before alerting)
- **Provenance:** Report-documented behavior

## Detection Logic
- Filters `DeviceFileEvents` to `FileCreated`, `FileModified` and `FileRenamed` (deletions are ignored) for web-executable extensions.
- Requires the writing process to be a web/database server (`w3wp`, `java`, `tomcat`, `httpd`, `nginx`, `php-fpm`, `mysqld`, `sqlservr`) **or** the path to be a web root (`wwwroot`, `webapps`, `htdocs`, `inetpub`, `public_html`).

## Relevant Tables
- `DeviceFileEvents`

## Tags
- Agentic Offense
- ARTEX
- Persistence
- Webshell
- MITRE ATT&CK: T1505.003 (Server Software Component: Web Shell)

## Search Query
```kql
let serverParents=dynamic(["w3wp.exe","java.exe","javaw.exe","tomcat.exe","httpd.exe","apache2","nginx","php-fpm","mysqld.exe","mysqld","sqlservr.exe"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName matches regex @"(?i)\.(jsp|jspx|aspx|ashx|php)$"
| where set_has_element(serverParents, tolower(InitiatingProcessFileName)) or FolderPath has_any ("wwwroot","webapps","htdocs","inetpub","public_html")
| project Timestamp, DeviceId, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

## False Positive Tuning
- Application deployments and patching.
- Exclude deployment tooling (msdeploy, CI agents) writing into web roots.
- Tighten by requiring a server process as the writer for higher fidelity.

## Triage Steps
1. Review the file content and whether it accepts commands/parameters.
2. Look for child processes of the web server after the drop.
3. Correlate with web-server access logs for requests to the new file.

## Note
File creation is not definitive malicious execution. Thresholds are starting points, not validated defaults — run as a hunt first.
