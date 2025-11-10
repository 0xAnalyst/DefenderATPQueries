# Rule Documentation: DNS Zone Export Commands Execution (PowerShell Command Audit)

## Description
Detects execution of **DNS zone enumeration/export** cmdlets via PowerShell — specifically `Export-DnsServerZone` and `Get-DnsServerZone`. Adversaries export DNS data to map internal hosts and services for lateral movement and targeting. This rule uses PowerShell command audit telemetry (e.g., `DeviceEvents` with `ActionType == "PowerShellCommand"`) and excludes the common benign COM host invocation from `MonitoringHost.exe -Embedding`.

- **Source context:** DFIR cases where attackers export DNS zones to discover internal hostnames and domain controllers (see DFIR Report patterns).

## Detection Logic
- Trigger when a PowerShell command event contains `Export-DnsServerZone` or `Get-DnsServerZone`.
- Exclude benign automation noise where PowerShell is invoked by known monitoring components (example: `MonitoringHost.exe -Embedding`).
- Scope to server-class systems (DNS servers, management hosts) and admin accounts to reduce false positives.
- Prioritise events when:
  - Non-admin accounts execute the cmdlets.
  - Execution occurs from non-DNS servers or workstations.
  - Execution happens during off-hours or outside approved maintenance windows.
- Correlate with:
  - Unusual DNS queries or mass DNS lookups from the same host.
  - Creation of local files (exports) in uncommon locations.
  - Subsequent lateral movement or privilege escalation activity within a short time window.

## Tags
- Discovery  
- Reconnaissance  
- DNS Enumeration  
- PowerShell  
- MITRE ATT&CK:  
  - **T1016** – System Network Configuration Discovery  
  - **T1046** – Network Service Discovery

## Search Query
```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("Export-DnsServerZone", "Get-DnsServerZone")
| where InitiatingProcessCommandLine != @"""MonitoringHost.exe"" -Embedding"
