# Rule : Cloud Object Read/Download Bursts

## Description
Detects a single account/IP reading or downloading a large number of unique cloud objects within 15 minutes. Once an agent locates accessible data it tends to pull it in bulk.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-014
- **Severity:** Medium (initial suggestion; tune before alerting)
- **Provenance:** Defender-authored behavioral extrapolation

## Detection Logic
- Filters `CloudAppEvents` where `ActionType` or `ActivityType` contains read/download keywords (`download`, `fileaccessed`, `filedownloaded`, `read`, `getfile`).
- Alerts on **≥ 100 events** touching **≥ 50 unique objects** in a 15-minute bin.

## Relevant Tables
- `CloudAppEvents`

## Tags
- Agentic Offense
- Collection
- Cloud
- Data Access
- MITRE ATT&CK: T1530 (Data from Cloud Storage)

## Search Query
```kql
let ReadKeywords=dynamic(["download","fileaccessed","filedownloaded","read","getfile"]);
CloudAppEvents
| where Timestamp > ago(24h)
| where ActionType has_any (ReadKeywords) or ActivityType has_any (ReadKeywords)
| summarize Events=count(), UniqueObjects=dcount(ObjectId), SampleNames=make_set(ObjectName,10), Actions=make_set(ActionType,8) by AccountId, Application, IPAddress, bin(Timestamp,15m)
| where Events >= 100 and UniqueObjects >= 50
| order by UniqueObjects desc
```

## False Positive Tuning
- Backup and sync operations.
- Exclude backup and sync clients.
- Validate the read keywords against your tenant: `CloudAppEvents | summarize count() by Application, ActionType`.

## Triage Steps
1. Review `SampleNames` for sensitive data.
2. Check for preceding high-velocity discovery from the same account (OAI-013).

## Note
ActionType read keywords are tenant/provider dependent; tune via schema. Thresholds are starting points, not validated defaults — run as a hunt first.
