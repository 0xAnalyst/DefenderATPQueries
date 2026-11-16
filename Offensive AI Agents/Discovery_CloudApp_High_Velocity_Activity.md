# Rule : Unusual Cloud Application API Activity Burst

## Description
Detects a single account/IP generating a high volume of varied SaaS actions in a short window in `CloudAppEvents`. Agent-driven enumeration of SaaS tenants produces many operations across many objects at machine speed.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-013
- **Severity:** Medium (initial suggestion; tune before alerting)
- **Provenance:** Defender-authored behavioral extrapolation

## Detection Logic
- Groups `CloudAppEvents` by account, application and IP in 5-minute bins.
- Alerts on **≥ 80 events** spanning **≥ 4 distinct action types**.

## Relevant Tables
- `CloudAppEvents`

## Tags
- Agentic Offense
- Discovery
- Cloud
- SaaS
- MITRE ATT&CK: T1087 (Account Discovery)

## Search Query
```kql
CloudAppEvents
| where Timestamp > ago(24h)
| where isnotempty(AccountId)
| summarize Events=count(), Operations=dcount(ActionType), Objects=dcount(ObjectId), Actions=make_set(ActionType,12), Examples=make_set(ObjectName,8), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by AccountId, Application, IPAddress, bin(Timestamp,5m)
| where Events >= 80 and Operations >= 4
| order by Events desc
```

## False Positive Tuning
- Automation and migrations.
- Exclude migration tools, backup connectors and integration service principals.

## Triage Steps
1. Review the `Actions` set for enumeration vs. data access.
2. Check sign-in logs for the account/IP — new ASN or country?

## Note
CloudAppEvents coverage/action types vary by connector. Thresholds are starting points, not validated defaults — run as a hunt first.
