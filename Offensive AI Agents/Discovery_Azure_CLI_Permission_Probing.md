# Rule : Azure CLI Permission and Storage Testing Burst

## Description
Detects bursts of Azure CLI / PowerShell commands that validate deployments, list storage keys, enumerate role assignments or test SAS / auth modes. The report describes aggressive permission probing by agentic frameworks once they obtain cloud credentials.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-009
- **Severity:** Medium (initial suggestion; tune before alerting)
- **Provenance:** Report-documented behavior

## Detection Logic
- Filters `DeviceProcessEvents` to `az`, PowerShell and `curl`, plus `python` processes running `azure.cli` — on Windows `az.cmd` launches `python.exe -IBm azure.cli`, so there is no `az.exe` process.
- Requires keywords such as `deployments validate`, `account keys list`, `storage blob`, `role assignment list`, `listKeys`, `what-if`, `--sas-token`.
- Alerts on **≥ 4 commands** with **≥ 3 distinct command lines** in 5 minutes.

## Relevant Tables
- `DeviceProcessEvents`

## Tags
- Agentic Offense
- ARTEX
- Discovery
- Cloud
- Azure
- MITRE ATT&CK: T1526 (Cloud Service Discovery)

## Search Query
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("az","az.exe","powershell.exe","pwsh.exe","curl.exe") or (FileName in~ ("python.exe","python3","python") and ProcessCommandLine has "azure.cli")
| where ProcessCommandLine has_any ("deployments validate","deployment group validate","account keys list","storage blob","role assignment list","listKeys","what-if","--auth-mode","--sas-token")
| summarize Count=count(), DistinctCommands=dcount(ProcessCommandLine), Samples=make_set(substring(ProcessCommandLine,0,220),8), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceId, DeviceName, AccountName, bin(Timestamp,5m)
| where Count >= 4 and DistinctCommands >= 3
| order by Count desc
```

## False Positive Tuning
- Infrastructure deployment pipelines.
- Exclude IaC pipelines and cloud-ops jump hosts.
- On Linux the `az` wrapper and its `python3` child can both be logged, which roughly doubles counts — raise thresholds there if needed.

## Triage Steps
1. Identify the identity used by the CLI session.
2. Pull `AzureActivity` for the same identity to see API results (success/failure).

## Note
Only catches local Azure CLI/script command lines; not Azure API logs. Thresholds are starting points, not validated defaults — run as a hunt first.
