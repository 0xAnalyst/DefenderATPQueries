# Rule : ARTEX-like Incremental Probe Artifacts

## Description
Detects files and command lines carrying the probe naming convention documented for the ARTEX agentic offensive framework (`artex-probe-*`, `ArtexProbe`). ARTEX drops numbered probe files while it incrementally tests write access, execution and payload placement on a compromised host. These names are framework artifacts published in the report, which makes this the highest-fidelity rule in the folder — but also the easiest one for an operator to evade by renaming.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-001
- **Severity:** High (initial suggestion; tune before alerting)
- **Provenance:** Report-documented artifact

## Detection Logic
- Searches `DeviceFileEvents` for file names matching `artex[-_]probe[-_]<3+ digits>`, containing `ArtexProbe`, or folder paths containing `artex-probe-`.
- Searches `DeviceProcessEvents` for command lines that reference `artex-probe-` or `ArtexProbe`.
- Unions both evidence types into one timeline with the device, account and artifact context.

## Relevant Tables
- `DeviceFileEvents`
- `DeviceProcessEvents`

## Tags
- Agentic Offense
- ARTEX
- Framework Artifact
- Masquerading
- MITRE ATT&CK: T1036 (Masquerading)

## Search Query
```kql
let lookback = 7d;
let file_hits = DeviceFileEvents
| where Timestamp > ago(lookback)
| where FileName matches regex @"(?i)artex[-_]?probe[-_]?\d{3,}" or FileName contains "ArtexProbe" or FolderPath contains "artex-probe-"
| project Timestamp, DeviceId, DeviceName, EvidenceType="File", Artifact=FileName, Context=FolderPath, Account=InitiatingProcessAccountName;
let process_hits = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine contains "artex-probe-" or ProcessCommandLine contains "ArtexProbe"
| project Timestamp, DeviceId, DeviceName, EvidenceType="Process", Artifact=FileName, Context=ProcessCommandLine, Account=AccountName;
union file_hits, process_hits
| order by Timestamp desc
```

## False Positive Tuning
- Authorized testing and copied samples.
- Exclude authorized red-team / purple-team hosts that replay ARTEX samples.
- Exclude malware-analysis sandboxes and threat-intel sample shares.

## Triage Steps
1. Confirm the file path and the process that wrote it.
2. Pull the process tree and 30 minutes of surrounding activity on the device.
3. Check for webhook egress (`webhook.site`) and AD discovery from the same device.
4. Hash the artifact and search for it across the estate.

## Note
Specific filenames can be changed. Thresholds are starting points, not validated defaults — run as a hunt first.
