## Rule:  Detection of Process Injection from Office apps throug ASR

### Description
This query detects events where an office process injection has been audited by the Advanced Security Audit Policy (ASR).

- [Microsoft documentation on ASR](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)

### Detection Logic
Monitors `DeviceEvents` for occurrences where the `ActionType` is `"AsrOfficeProcessInjectionAudited"`.

### Tags
- ASR
- Office
- Process Injection
- Auditing

### Search Query
```kql
DeviceEvents
| where ActionType == "AsrOfficeProcessInjectionAudited"
```
