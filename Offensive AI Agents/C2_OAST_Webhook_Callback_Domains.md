# Rule : OAST, Webhook, and Disposable Callback Destinations

## Description
Detects connections to out-of-band testing (OAST) and disposable callback services — `webhook.site`, `interact.sh`, `oast.pro`, `oast.live`, `burpcollaborator.net`, `requestbin.net`, `pipedream.net`. Agentic offensive frameworks and tools like Hexstrike use these to confirm blind vulnerabilities and receive data.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-018
- **Severity:** Medium (initial suggestion; tune before alerting)
- **Provenance:** Defender-authored behavioral extrapolation

## Detection Logic
- Parses the host from `RemoteUrl` in `DeviceNetworkEvents`.
- Matches against the callback-domain list.
- Summarizes per device, process and account in 1-hour bins.

## Relevant Tables
- `DeviceNetworkEvents`

## Tags
- Agentic Offense
- Command and Control
- OAST
- Webhook
- MITRE ATT&CK: T1071.001 (Application Layer Protocol: Web Protocols)

## Search Query
```kql
let CallbackDomains=dynamic(["webhook.site","interact.sh","oast.pro","oast.live","burpcollaborator.net","requestbin.net","pipedream.net"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| extend Host=tolower(tostring(parse_url(strcat("https://",RemoteUrl)).Host))
| where Host has_any (CallbackDomains) or RemoteUrl has_any (CallbackDomains)
| summarize Connections=count(), UniqueDestinations=dcount(RemoteUrl), SampleDestinations=make_set(RemoteUrl,10) by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, bin(Timestamp,1h)
| order by Connections desc
```

## False Positive Tuning
- Security tests and webhook development.
- Exclude AppSec / pentest devices.
- Extend `CallbackDomains` with providers seen in your threat intel.

## Triage Steps
1. Identify the process making the callback.
2. If the device is a server, treat a callback as possible successful exploitation.

## Note
Provider domains are dual-use, not inherently malicious. Thresholds are starting points, not validated defaults — run as a hunt first.
