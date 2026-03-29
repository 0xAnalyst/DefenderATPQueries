# Rule Documentation: VS Code Folder Open Task Execution

## Description
Detects malicious VS Code tasks configured with runOn: folderOpen for automatic execution.

## Detection Logic
- File events on .vscode/tasks.json

## MITRE ATT&CK
- T1053 – Scheduled Task / Job
- T1204 – User Execution

## Tags
Persistence, VSCode, Supply Chain

## Search Query
```kql
DeviceFileEvents
| where FolderPath has ".vscode"
| where FileName =~ "tasks.json"
```

## References
- VS Code Tasks Abuse
- PolinRider Attack
