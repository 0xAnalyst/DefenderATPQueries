# Rule : Correlation of Git Abuse with VS Code Task or Workspace Triggering

## Description
Correlates Git abuse activity with suspicious VS Code or workspace-triggered execution. This analytic is useful for detecting the full chain where repository tampering is followed by malicious execution through IDE tasking.

## Detection Logic
This correlation looks for:
- Git amend or force push behavior
- Node execution of masqueraded content
- VS Code or shell-related initiating process context

## Relevant Tables
- `DeviceProcessEvents`

## Search Query
```kql
let GitAbuse = DeviceProcessEvents
| where ProcessCommandLine has_any ("git commit --amend", "--no-verify", "git push -f", "git push --force", "git config --local")
| project DeviceId, GitTime=Timestamp, DeviceName, AccountName, GitCmd=ProcessCommandLine;
let SuspiciousNode = DeviceProcessEvents
| where FileName in~ ("node.exe", "node")
| where ProcessCommandLine has_any (".woff2", ".woff", ".ttf", ".otf", ".eot")
| where InitiatingProcessFileName in~ ("Code.exe", "code", "cmd.exe", "powershell.exe", "bash", "sh", "zsh")
   or InitiatingProcessCommandLine has_any ("Code.exe", "code", ".vscode", "tasks.json", "folderOpen")
| project DeviceId, NodeTime=Timestamp, NodeCmd=ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
GitAbuse
| join kind=inner SuspiciousNode on DeviceId
| where NodeTime between (GitTime - 7d .. GitTime + 7d)
| project DeviceName, AccountName, GitTime, GitCmd, NodeTime, NodeCmd, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by NodeTime desc
```

## False Positive Tuning
- Scope initially to developer endpoints.
- Exclude known benign static analysis or packaging workflows if any exist.
- Prioritize repositories with external contributors or recent suspicious history rewrites.

## Triage Steps
1. Determine whether Git abuse preceded malicious execution on the same endpoint.
2. Review the repository for `.vscode/tasks.json`, hidden scripts, and disguised payloads.
3. Check network activity from Node for unusual infrastructure or payload retrieval.
4. Validate whether the repository was recently cloned, modified, or opened in the IDE.
5. Escalate as a likely supply chain compromise if both sides of the correlation are present.

## Investigation Notes
- High value for detecting end-to-end developer compromise.
