## Rule : Web shell Detection on exchange servers with ASR

### Description
This query detects events where a web shell on a server has been audited by the Advanced Security Audit Policy (ASR). Web shells are malicious scripts that enable remote administration on web servers, often used by attackers for persistent access and to execute arbitrary commands.

- [Microsoft documentation on ASR](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)

### Detection Logic
Monitors `DeviceEvents` for occurrences where the `ActionType` is `'AsrWebShellOnServerAudited'`.

### Tags
- ASR
- Web Shell
- Server Security
- Auditing

### Search Query
```kql
DeviceEvents
| where ActionType == 'AsrWebShellOnServerAudited'
```
