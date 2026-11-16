# Rule : Multiple Unique Webhook Endpoints Contacted by One Device

## Description
Detects a device contacting several distinct `webhook.site` URLs within a short window. ARTEX rotated webhook endpoints during operations; a device hitting many distinct webhook URLs in 15 minutes is unusual even for developers.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-004
- **Severity:** High (initial suggestion; tune before alerting)
- **Provenance:** Report-documented behavior

## Detection Logic
- Filters `DeviceNetworkEvents` for `RemoteUrl` containing `webhook.site`.
- Groups by device, account and 15-minute bin.
- Alerts on **≥ 5 connections** to **≥ 3 distinct URLs**.

## Relevant Tables
- `DeviceNetworkEvents`

## Tags
- Agentic Offense
- ARTEX
- Exfiltration
- Webhook
- MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel)

## Search Query
```kql
let lookback=24h;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl contains "webhook.site"
| summarize Connections=count(), DistinctUrls=dcount(RemoteUrl), UrlExamples=make_set(RemoteUrl,12), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Processes=make_set(InitiatingProcessFileName,8) by DeviceId, DeviceName, InitiatingProcessAccountName, bin(Timestamp,15m)
| where Connections >= 5 and DistinctUrls >= 3
| order by Connections desc
```

## False Positive Tuning
- Authorized callbacks and synthetic monitoring.
- Exclude synthetic monitoring and authorized callback testing.

## Triage Steps
1. Compare the URL list with the process command lines on the device.
2. Pull HTTP proxy logs for the full paths/UUIDs.

## Note
Hostname-only telemetry may collapse many distinct webhook paths; count URLs not tokens. Thresholds are starting points, not validated defaults — run as a hunt first.
