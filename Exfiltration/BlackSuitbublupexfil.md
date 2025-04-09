# Rule : Detection of Data Exfiltration to Bublup.com

## Description
This detection rule identifies potential **data exfiltration** attempts by monitoring network connections to `bublup.com`, a legitimate file sharing and storage platform that has been **abused by threat actors**, including the **BlackSuit ransomware group**. During documented intrusions, adversaries used this service to upload exfiltrated data, often as part of double extortion campaigns.

Connections to `bublup.com` may be uncommon in enterprise environments. When observed—especially outside known business workflows—they may represent staging or exfiltration activity in the later stages of an attack.

- [The DFIR Report: Fake Zoom Ends in BlackSuit Ransomware](https://thedfirreport.com/2025/03/31/fake-zoom-ends-in-blacksuit-ransomware/)
- [Unit 42: BlackSuit Ransomware – Ignoble Scorpius](https://unit42.paloaltonetworks.com/threat-assessment-blacksuit-ransomware-ignoble-scorpius/)

## Detection Logic
- Monitors `DeviceNetworkEvents` where:
  - The `RemoteUrl` contains `"bublup.com"`.

## Tags
- Data Exfiltration
- Cloud Abuse
- Bublup
- BlackSuit Ransomware
- Post-Exploitation
- Suspicious Network Activity

## Search Query
```kql
DeviceNetworkEvents
| where RemoteUrl contains "bublup.com"
```
