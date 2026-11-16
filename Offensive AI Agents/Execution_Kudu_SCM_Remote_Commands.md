# Rule : Kudu SCM API and Remote Execution Visible in Process Command Lines

## Description
Detects command lines that call Azure App Service Kudu/SCM APIs (`/api/command`, `/api/zipdeploy`, `/api/vfs/`, `/api/processes`, `scm.azurewebsites.net`). Kudu gives remote command execution and file access on App Service workloads — attractive to an agent that has obtained publishing credentials.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-017
- **Severity:** High (initial suggestion; tune before alerting)
- **Provenance:** Defender-authored behavioral extrapolation

## Detection Logic
- Searches `DeviceProcessEvents` for Kudu API paths or `scm.azurewebsites.net` in the command line.
- Restricts to `curl`, PowerShell, Python, shells and `az`.

## Relevant Tables
- `DeviceProcessEvents`

## Tags
- Agentic Offense
- Execution
- Cloud
- Azure App Service
- MITRE ATT&CK: T1059 (Command and Scripting Interpreter)

## Search Query
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("/api/command","/api/zipdeploy","/api/vfs/","scm.azurewebsites.net","/api/processes")
| where FileName in~ ("curl.exe","curl","powershell.exe","pwsh.exe","python.exe","python3","bash","sh","az.exe","az")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## False Positive Tuning
- Authorized App Service deployment.
- Exclude deployment pipelines that use `zipdeploy`.

## Triage Steps
1. Identify the target app and the credential used.
2. Review App Service logs for commands executed via `/api/command`.

## Note
Requires process CLI visibility and will miss server-side API requests. Thresholds are starting points, not validated defaults — run as a hunt first.
