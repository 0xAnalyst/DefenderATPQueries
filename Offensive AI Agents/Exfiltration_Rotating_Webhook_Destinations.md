# Rule : Multiple Unique Webhook Endpoints Contacted by One Device

## Description
Detects a device using several distinct `webhook.site` endpoints (webhook UUIDs) within a short window. ARTEX rotated webhook endpoints during operations; a device hitting many distinct webhook URLs in 15 minutes is unusual even for developers.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-004
- **Severity:** High (initial suggestion; tune before alerting)
- **Provenance:** Report-documented behavior

## Detection Logic
- Collects `webhook.site` references from `DeviceProcessEvents` command lines and `DeviceNetworkEvents` (`RemoteUrl` + initiating command line).
- Extracts webhook UUIDs (`webhook.site/<uuid>`) with `extract_all`, because `RemoteUrl` usually holds only the host name.
- Groups by device, account and 15-minute bin.
- Alerts on **≥ 3 distinct webhook UUIDs**, or **≥ 10 webhook events** when no UUID is visible.

## Relevant Tables
- `DeviceProcessEvents`
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
let webhook_id_regex=@"(?i)webhook\.site/(?:token/)?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})";
let from_process=DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has "webhook.site"
| project Timestamp, DeviceId, DeviceName, AccountName, Process=FileName, Evidence=ProcessCommandLine;
let from_network=DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl has "webhook.site"
| project Timestamp, DeviceId, DeviceName, AccountName=InitiatingProcessAccountName, Process=InitiatingProcessFileName, Evidence=strcat(RemoteUrl," | ",InitiatingProcessCommandLine);
union from_process, from_network
| extend WebhookIds=extract_all(webhook_id_regex, Evidence)
| extend WebhookIds=iff(array_length(WebhookIds) == 0, dynamic([""]), WebhookIds)
| mv-expand WebhookId=WebhookIds to typeof(string)
| summarize Events=count(), DistinctWebhookIds=dcountif(WebhookId, isnotempty(WebhookId)), WebhookIdExamples=make_set_if(WebhookId, isnotempty(WebhookId), 12), Processes=make_set(Process,8), Examples=make_set(substring(Evidence,0,200),6), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceId, DeviceName, AccountName, bin(Timestamp,15m)
| where DistinctWebhookIds >= 3 or Events >= 10
| order by DistinctWebhookIds desc, Events desc
```

## False Positive Tuning
- Authorized callbacks and synthetic monitoring.
- Exclude synthetic monitoring and authorized callback testing.

## Triage Steps
1. Compare the URL list with the process command lines on the device.
2. Pull HTTP proxy logs for the full paths/UUIDs.

## Note
UUIDs are only visible when they appear in a command line or full URL; hostname-only network events fall back to the volume threshold. A command line holding several UUIDs counts once per UUID in `Events`. Thresholds are starting points, not validated defaults — run as a hunt first.
