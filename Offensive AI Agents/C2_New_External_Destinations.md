# Rule : New External FQDNs Contacted by Workload

## Description
Detects devices that suddenly contact five or more external domains they have not contacted in the previous 14 days. A compromised workload driven by an agent tends to reach out to new tooling, callback and staging infrastructure.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-012
- **Severity:** Medium (initial suggestion; tune before alerting)
- **Provenance:** Defender-authored behavioral extrapolation

## Detection Logic
- Builds a 14-day baseline of `DeviceId` + `RemoteUrl` pairs from `DeviceNetworkEvents` (public IPs only).
- Left-anti joins the last 24 hours against that baseline.
- Alerts on **≥ 5 new domains** per device/account in a 1-hour bin.

## Relevant Tables
- `DeviceNetworkEvents`

## Tags
- Agentic Offense
- Command and Control
- Baseline
- New Destination
- MITRE ATT&CK: T1071.001 (Application Layer Protocol: Web Protocols)

## Search Query
```kql
let baseline=14d;
let recent=1d;
let older=DeviceNetworkEvents
| where Timestamp between (ago(baseline)..ago(recent))
| where isnotempty(RemoteUrl) and ipv4_is_private(RemoteIP) == false
| summarize by DeviceId, RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(recent)
| where isnotempty(RemoteUrl) and ipv4_is_private(RemoteIP) == false
| join kind=leftanti older on DeviceId, RemoteUrl
| summarize Connections=count(), NewDomains=dcount(RemoteUrl), DomainExamples=make_set(RemoteUrl,15), Processes=make_set(InitiatingProcessFileName,8) by DeviceId, DeviceName, InitiatingProcessAccountName, bin(Timestamp,1h)
| where NewDomains >= 5
| order by NewDomains desc
```

## False Positive Tuning
- Software updates and freshly provisioned machines.
- Scope to servers / DMZ device groups for higher signal.
- Exclude software-update and CDN domains seen across many devices.

## Triage Steps
1. Review the new domains for tooling (GitHub raw, paste sites), callback or tunneling services.
2. Check the initiating processes list.

## Note
Baseline is 14d and can be incomplete due to retention; not server-only unless scoped. Thresholds are starting points, not validated defaults — run as a hunt first.
