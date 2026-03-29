# Rule : Suspicious Node.js Execution of Masqueraded Font Payload

## Description
Detects Node.js executing font/static asset extensions (e.g., .woff2) indicating masquerading and malicious execution.

## Detection Logic
- Node process execution
- Command line contains .woff/.woff2/.ttf/.otf

## MITRE ATT&CK
- T1059 – Command and Scripting Interpreter
- T1027 – Obfuscated Files or Information

## Tags
Execution, Defense Evasion, Masquerading, Supply Chain

## Search Query
```kql
DeviceProcessEvents
| where FileName in~ ("node.exe", "node")
| where ProcessCommandLine has_any (".woff", ".woff2", ".ttf", ".otf")
```

## References
- PolinRider Campaign
- OpenSourceMalware research
