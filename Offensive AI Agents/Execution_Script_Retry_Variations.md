# Rule : Multiple Distinct Scripted Command Variations in a Short Window

## Description
Detects one interpreter on one device running many slightly different long command lines within 2 minutes. When an agent's command fails it rewrites and retries it — producing a tight cluster of variants that is uncommon for humans.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-016
- **Severity:** Medium (initial suggestion; tune before alerting)
- **Provenance:** Defender-authored behavioral extrapolation

## Detection Logic
- Filters `DeviceProcessEvents` to PowerShell, Python, `cmd`, `bash`, `sh` with command lines longer than 50 characters.
- Alerts on **≥ 10 attempts** with **≥ 8 distinct variants** in a 2-minute bin per device/account/interpreter.

## Relevant Tables
- `DeviceProcessEvents`

## Tags
- Agentic Offense
- Execution
- Behavioral
- Retry Pattern
- MITRE ATT&CK: T1059 (Command and Scripting Interpreter)

## Search Query
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe","pwsh.exe","python.exe","python3","cmd.exe","bash","sh")
| where strlen(ProcessCommandLine) > 50
| summarize Attempts=count(), Variants=dcount(ProcessCommandLine), Samples=make_set(substring(ProcessCommandLine,0,200),10), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceId, DeviceName, AccountName, FileName, bin(Timestamp,2m)
| where Attempts >= 10 and Variants >= 8
| order by Variants desc
```

## False Positive Tuning
- Software development and deployment retries.
- Exclude developer workstations and deployment retry loops.

## Triage Steps
1. Diff the `Samples` — do they look like iterative fixes of the same goal (quoting, flags, paths)?
2. Identify the parent process driving the interpreter.

## Note
This detects retries/variation, not actual error messages or AI. Thresholds are starting points, not validated defaults — run as a hunt first.
