# Rule : AWS CLI Permission Dry Runs and Metadata Probes

## Description
Detects bursts of AWS CLI activity using `--dry-run`, `get-caller-identity`, snapshot/volume/security-group enumeration, `run-instances` and `create-volume`. `--dry-run` is the canonical way to test IAM permissions without making changes — exactly what an agent does when mapping what stolen keys can reach.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-010
- **Severity:** Medium (initial suggestion; tune before alerting)
- **Provenance:** Report-documented behavior

## Detection Logic
- Filters `DeviceProcessEvents` to `aws`, shells and PowerShell.
- Requires AWS permission-probing keywords in the command line.
- Alerts on **≥ 4 commands** with **≥ 3 distinct command lines** in 5 minutes.

## Relevant Tables
- `DeviceProcessEvents`

## Tags
- Agentic Offense
- ARTEX
- Discovery
- Cloud
- AWS
- MITRE ATT&CK: T1526 (Cloud Service Discovery)

## Search Query
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("aws","aws.exe","bash","sh","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("--dry-run","get-caller-identity","describe-snapshots","describe-volumes","describe-iam-instance-profile-associations","run-instances","create-volume","describe-security-groups")
| summarize Count=count(), DistinctCommands=dcount(ProcessCommandLine), Samples=make_set(substring(ProcessCommandLine,0,220),8), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceId, DeviceName, AccountName, bin(Timestamp,5m)
| where Count >= 4 and DistinctCommands >= 3
| order by Count desc
```

## False Positive Tuning
- Cloud operations and IaC pipelines.
- Exclude IaC pipelines and cloud-ops engineers' devices.

## Triage Steps
1. Identify the AWS profile / access key in use.
2. Review CloudTrail for `DryRunOperation` / `UnauthorizedOperation` from the same key.

## Note
Only catches local AWS CLI/script command lines; not CloudTrail events. Thresholds are starting points, not validated defaults — run as a hunt first.
