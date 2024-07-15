## Rule: Detection of untrusted processe running for USB by ASR  

### Description
This query detects events where an untrusted USB process has been audited by the Advanced Security Audit Policy (ASR).

- [Microsoft documentation on ASR](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)

### Detection Logic
Monitors `DeviceEvents` for occurrences where the `ActionType` is `"AsrUntrustedUsbProcessAudited"`.

### Tags
- ASR
- USB
- Auditing

### Search Query
```kql
DeviceEvents
| where ActionType == "AsrUntrustedUsbProcessAudited"
```
