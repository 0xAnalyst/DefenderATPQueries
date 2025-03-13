# Rule : Suspicious Node.js Process Execution with PowerShell

## Description
This detection rule identifies suspicious executions of `node.exe` that include potentially malicious command-line arguments. Attackers often use Node.js (`node.exe`) to execute system commands, including PowerShell, to gain unauthorized access, execute malicious scripts, or establish persistence on a compromised system.

By monitoring Node.js processes with command-line arguments containing HTTP-related operations (`http`), child process creation functions (`spawn`, `execSync`), JavaScript constants (`const`), and PowerShell execution, this rule helps detect potential exploitation, malware execution, or unauthorized command execution.

## Detection Logic
- **Monitors `DeviceProcessEvents`** for processes where:
  - The `FileName` contains `"node.exe"`, and
  - The `ProcessCommandLine` contains all of the following indicators:
    - `"http"` (indicating potential external network connections)
    - `"spawn"` or `"execSync"` (indicating child process creation)
    - `"const"` (a JavaScript keyword commonly used in malicious scripts)
    - `"powershell"` (indicating potential command execution via PowerShell)

## Tags
- Node.js Execution
- PowerShell Execution
- Suspicious Command Execution
- Process Monitoring
- Code Execution via Node.js

## Search Query
```kql
DeviceProcessEvents
| where FileName contains "node.exe"
| where ProcessCommandLine has_all ("http", "spawn", "execSync", "const", "powershell")
