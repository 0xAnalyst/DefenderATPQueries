# Rule : Command-Output Transfer to Webhooks

## Description
Detects command-line tools and network connections that send data to `webhook.site`. The report documents ARTEX posting the output of its commands to webhook endpoints as a lightweight exfiltration and feedback channel back to the agent operator.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-003
- **Severity:** High (initial suggestion; tune before alerting)
- **Provenance:** Report-documented behavior

## Detection Logic
- Searches `DeviceProcessEvents` for command lines containing `webhook.site` executed by `curl`, PowerShell, `cmd`, `bash`/`sh`, or using `Invoke-WebRequest` / `Invoke-RestMethod`.
- Searches `DeviceNetworkEvents` for connections where `RemoteUrl` contains `webhook.site`.
- Unions both into one timeline with the initiating command line.

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
let lookback = 7d;
let suspicious_processes = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has "webhook.site" and (FileName in~ ("curl.exe","curl","powershell.exe","pwsh.exe","cmd.exe","bash","sh") or ProcessCommandLine has_any ("curl","Invoke-WebRequest","Invoke-RestMethod"))
| project Timestamp, DeviceId, DeviceName, Evidence="Process invocation", AccountName, Details=ProcessCommandLine;
let suspicious_network = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl contains "webhook.site"
| project Timestamp, DeviceId, DeviceName, Evidence="Network connection", AccountName=InitiatingProcessAccountName, Details=strcat(RemoteUrl," | ",InitiatingProcessCommandLine);
union suspicious_processes, suspicious_network
| order by Timestamp desc
```

## False Positive Tuning
- Webhook development and IT integrations.
- Exclude developers and integration teams who use webhook.site for testing (by device group, not globally).

## Triage Steps
1. Inspect the command line for piped command output (`whoami`, `net group`, `Get-AD*`) being posted.
2. Look for discovery commands immediately preceding the request.
3. Block the destination at the proxy if the activity is not authorized.

## Note
Requires endpoint visibility into command lines or network FQDN. Thresholds are starting points, not validated defaults — run as a hunt first.
