# Rule : Detection of LSASS Credential Theft Audited

## Description
This detection rule identifies audited events where attempts to steal credentials from the Local Security Authority Subsystem Service (LSASS) process are detected. LSASS is a critical process that handles security policy and user authentication. Malicious actors often target LSASS to extract credentials and escalate privileges. This rule focuses on identifying rare instances of processes attempting to access LSASS, as frequent attempts may indicate a targeted attack.

This rule helps detect and audit suspicious processes interacting with LSASS, providing an early warning for potential credential theft activities.

- [Detect and Block Credential Dumps with Defender for Endpoint](https://jeffreyappel.nl/detect-and-block-credential-dumps-with-defender-for-endpoint-attack-surface-reduction/)

## Detection Logic
- Monitors `DeviceEvents` for events where:
  - The `ActionType` is "AsrLsassCredentialTheftAudited".
  - The `Timestamp` is within the last 30 days.
- Summarizes the count of unique devices and rule hits by the `FileName` and `InitiatingProcessFileName`.
- Filters for events where the count of unique devices is less than 3.
- Sorts the results by the count of unique devices in descending order.

## Tags
- Credential Theft
- LSASS
- Malware
- Advanced Security Rules (ASR)
- Suspicious Activity

## Search Query
```kql
DeviceEvents
| where ActionType == "AsrLsassCredentialTheftAudited" and Timestamp > ago(30d)
//| project BlockedProcess=FileName, ParentProcess=InitiatingProcessFileName, DeviceName
| summarize Devicecount=dcount(DeviceName), RuleHits=count() by FileName, InitiatingProcessFileName 
| where Devicecount < 3
| sort by Devicecount desc
```
## Notes
This is very noisy rule
