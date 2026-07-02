# Rule : Possible Data Exfiltration - Unusual Outbound Upload from Internal Host

## Description
Detects potential data exfiltration when an internal source IP sends a large amount of outbound data to the internet, especially when the volume is significantly higher than its normal behavior.

## Detection Logic
This query alerts when:
- Source IP is internal/private
- Destination IP is external/public
- Firewall action is allowed
- Data sent is more than 500 MB in 1 hour
- Traffic is mostly upload traffic, with upload ratio greater than 95%

## MITRE ATT&CK
- T1048 - Exfiltration Over Alternative Protocol
- T1567 - Exfilteration Over Web Service
- T1020 - Automated Exfilteration

## Tags
DataExfiltration, Firewall, CommonSecurityLog, LargeOutboundUpload, InternalToExternal, UploadRatioAnomaly

## Search Query
```kql
let MinUploadBytes = 500000000; // 500 MB
let PrivateIPRegex = @"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"; // regex matches private IPs
CommonSecurityLog
| where TimeGenerated > ago(1h) // lokks for last 1 hour logs
| where isnotempty(SourceIP) // where sourceIP is parsed
| where isnotempty(DestinationIP) // where destinationIP is parsed
| where SourceIP matches regex PrivateIPRegex
| where not(DestinationIP matches regex PrivateIPRegex)
| where DeviceAction in~ ("allow", "allowed", "accept", "accepted", "permitted")
| where isnotempty(SentBytes)
| summarize
    TotalBytesSent = sum(tolong(SentBytes)),
    TotalBytesReceived = sum(tolong(ReceivedBytes)),
    Connections = count(),
    DestinationIPs = make_set(DestinationIP, 20),
    DestinationPorts = make_set(DestinationPort, 20),
    Applications = make_set(ApplicationProtocol, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP
| where TotalBytesSent >= MinUploadBytes
| extend TotalGBSent = round(TotalBytesSent / 1024.0 / 1024.0 / 1024.0, 2)
| extend TotalGBReceived = round(TotalBytesReceived / 1024.0 / 1024.0 / 1024.0, 2)
| extend UploadRatio = round(todouble(TotalBytesSent) / todouble(TotalBytesSent + TotalBytesReceived) * 100, 2)
| where UploadRatio >= 95
| project
    TimeGenerated = LastSeen,
    SourceIP,
    TotalGBSent,
    TotalGBReceived,
    UploadRatio,
    Connections,
    DestinationIPs,
    DestinationPorts,
    Applications,
    FirstSeen,
    LastSeen
| order by TotalGBSent desc
```

## References
- [MITRE ATT&CK - T1567](https://attack.mitre.org/techniques/T1567/)
- [MITRE ATT&CK - T1567](https://attack.mitre.org/techniques/T1567/)
- [AMA](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/commonsecuritylog)
- [CEF](https://learn.microsoft.com/en-us/azure/sentinel/cef-name-mapping)