# Rule : AD Reconnaissance Followed by Webhook Egress on the Same Device

## Description
Correlates AD discovery commands with `webhook.site` connections on the same device within 30 minutes. This reproduces the ARTEX sequence of enumerating the domain and posting the results back to a webhook — the combination is far stronger than either signal alone.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-015
- **Severity:** High (initial suggestion; tune before alerting)
- **Provenance:** Report-documented sequence

## Detection Logic
- Summarizes AD-discovery command lines per device from `DeviceProcessEvents`.
- Keeps every `webhook.site` connection from `DeviceNetworkEvents` (not just the first), so earlier benign webhook use on the device does not hide the attack.
- Inner-joins on `DeviceId` and requires **≥ 3 recon commands** and at least one webhook connection between the first recon command and 30 minutes after the last; only in-window connections are counted.

## Relevant Tables
- `DeviceProcessEvents`
- `DeviceNetworkEvents`

## Tags
- Agentic Offense
- ARTEX
- Correlation
- Discovery
- Exfiltration
- MITRE ATT&CK: T1087 (Account Discovery), T1041 (Exfiltration Over C2 Channel)

## Search Query
```kql
let lookback=24h;
let Recon=DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has_any ("Get-ADUser","Get-ADComputer","Get-ADGroup","/dclist","Domain Admins","ldapsearch","setspn")
| summarize ReconCount=count(), ReconFirst=min(Timestamp), ReconLast=max(Timestamp), ReconCommands=make_set(substring(ProcessCommandLine,0,140),6) by DeviceId, DeviceName;
let Egress=DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl contains "webhook.site"
| project DeviceId, EgressTime=Timestamp, RemoteUrl;
Recon
| where ReconCount >= 3
| join kind=inner Egress on DeviceId
| where EgressTime between (ReconFirst .. (ReconLast + 30m))
| summarize EgressCount=count(), EgressFirst=min(EgressTime), EgressLast=max(EgressTime), EgressUrls=make_set(RemoteUrl,8), ReconCommands=take_any(ReconCommands) by DeviceId, DeviceName, ReconCount, ReconFirst, ReconLast
| project DeviceId, DeviceName, ReconCount, ReconFirst, ReconLast, EgressCount, EgressFirst, EgressLast, ReconCommands, EgressUrls
| order by EgressFirst desc
```

## False Positive Tuning
- Red teams and admin automation.
- Exclude authorized red-team devices.

## Triage Steps
1. Treat as high priority — review both `ReconCommands` and `EgressUrls`.
2. Isolate the device if the activity is not authorized and pull the full timeline.

## Note
Same-device and timing correlation does not establish causation. Thresholds are starting points, not validated defaults — run as a hunt first.
