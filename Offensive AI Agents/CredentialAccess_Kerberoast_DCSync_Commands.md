# Rule : Potential Kerberoasting and DCSync Command Patterns

## Description
Detects command lines referencing well-known Kerberoasting and DCSync tooling (`GetUserSPNs`, `Invoke-Kerberoast`, `Rubeus`, `lsadump::dcsync`, `secretsdump`, `Get-ADReplAccount`). Agentic frameworks chain AD discovery directly into credential access using these public tools.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-006
- **Severity:** High (initial suggestion; tune before alerting)
- **Provenance:** Defender-authored behavioral extrapolation

## Detection Logic
- Searches `DeviceProcessEvents` for Kerberoasting / DCSync keywords in `ProcessCommandLine`.
- Labels each hit as `DCSync-related command`, `Kerberoasting-related command` or `Credential access keyword`.

## Relevant Tables
- `DeviceProcessEvents`

## Tags
- Agentic Offense
- Credential Access
- Kerberoasting
- DCSync
- MITRE ATT&CK: T1558.003 (Kerberoasting), T1003.006 (OS Credential Dumping: DCSync)

## Search Query
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("GetUserSPNs", "Invoke-Kerberoast", "Rubeus", "lsadump::dcsync", "secretsdump", "Get-ADReplAccount", "DCSync", "krbtgt")
| extend Signal=case(ProcessCommandLine has_any ("lsadump::dcsync","secretsdump","Get-ADReplAccount","DCSync"),"DCSync-related command", ProcessCommandLine has_any ("GetUserSPNs","Invoke-Kerberoast","Rubeus"),"Kerberoasting-related command","Credential access keyword")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine, Signal, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## False Positive Tuning
- Authorized red teams and domain administrators.
- Exclude authorized red-team devices.
- The `krbtgt` keyword alone can match legitimate password-rotation scripts — review before excluding.

## Triage Steps
1. Identify the targeted accounts/SPNs.
2. Check Defender for Identity for replication or TGS-request alerts from the same host.
3. If confirmed, rotate the affected service-account passwords (and `krbtgt` twice for DCSync).

## Note
Command-pattern hunt only; DCSync RPC network replication requires dedicated telemetry. Thresholds are starting points, not validated defaults — run as a hunt first.
