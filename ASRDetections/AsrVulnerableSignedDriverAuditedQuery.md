## Rule: Detect loading for Vulnerable devices using ASR

### Description
This query detects events where a vulnerable signed driver has been audited by the Advanced Security Audit Policy (ASR), excluding specific processes such as "HP Touchpoint Analytics Client" and "ASUSTeK Computer Inc.".

- [Microsoft documentation on ASR](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)

### Detection Logic
Monitors `DeviceEvents` for occurrences where:
- `ActionType` is `"AsrVulnerableSignedDriverAudited"`
- Excludes entries where `InitiatingProcessVersionInfoFileDescription` is `"HP Touchpoint Analytics Client"`
- Excludes entries where `InitiatingProcessVersionInfoCompanyName` is `"ASUSTeK Computer Inc."`

### Tags
- ASR
- Driver Security
- Auditing

### Search Query
```kql
DeviceEvents
| where ActionType == "AsrVulnerableSignedDriverAudited"
| where InitiatingProcessVersionInfoFileDescription != "HP Touchpoint Analytics Client"
| where InitiatingProcessVersionInfoCompanyName != "ASUSTeK Computer Inc."
