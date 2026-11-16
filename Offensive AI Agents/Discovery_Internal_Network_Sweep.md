# Rule : Rapid East-West Port and Host Scanning

## Description
Detects a single process connecting to many internal hosts across administrative and database ports (SSH, Kerberos, RPC, SMB, LDAP, MSSQL, Oracle, MySQL, RDP, PostgreSQL, WinRM, alt-HTTP). Agentic frameworks typically run broad internal service discovery before choosing a lateral-movement path.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-011
- **Severity:** High (initial suggestion; tune before alerting)
- **Provenance:** Defender-authored behavioral extrapolation

## Detection Logic
- Filters `DeviceNetworkEvents` to private `RemoteIP` values on a list of high-value ports.
- Groups by device, initiating process and account in 5-minute bins.
- Alerts on **≥ 12 distinct hosts** across **≥ 3 distinct ports**.

## Relevant Tables
- `DeviceNetworkEvents`

## Tags
- Agentic Offense
- Discovery
- Network Scanning
- Lateral Movement
- MITRE ATT&CK: T1046 (Network Service Discovery)

## Search Query
```kql
let lookback=24h;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ipv4_is_private(RemoteIP) == true
| where RemotePort in (22,88,135,139,389,445,636,1433,1521,3306,3389,5432,5985,5986,8080,8443)
| summarize Connections=count(), DistinctHosts=dcount(RemoteIP), DistinctPorts=dcount(RemotePort), Ports=make_set(RemotePort,20), Targets=make_set(RemoteIP,12) by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, bin(Timestamp,5m)
| where DistinctHosts >= 12 and DistinctPorts >= 3
| order by DistinctHosts desc
```

## False Positive Tuning
- Vulnerability scanners and management systems.
- Exclude vulnerability scanners, monitoring and management servers by device.

## Triage Steps
1. Identify the scanning process and its parent.
2. Check whether any scanned host was subsequently logged on to from this device.

## Note
Device network events may be sampled and ports incomplete. Thresholds are starting points, not validated defaults — run as a hunt first.
