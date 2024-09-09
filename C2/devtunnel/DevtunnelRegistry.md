# Rule Documentation: Devtunnel Detection through Registry Modifications Involving `InProcServer32` and MSAL Runtime

## Description
This detection rule identifies suspicious modifications to the `InProcServer32` registry key where the registry value data contains "msalruntime." Modifying this registry key can be an indication of persistence or DLL injection attacks. The `InProcServer32` key is commonly associated with Component Object Model (COM) hijacking, where adversaries attempt to load malicious DLLs through legitimate processes.

This rule is important for monitoring persistence techniques where the MSAL (Microsoft Authentication Library) runtime may be abused to perform unauthorized code execution or maintain persistent access to a compromised machine. By leveraging COM hijacking, threat actors can inject malicious code into trusted processes, effectively evading detection.

- [SigmaHQ Rule for DevTunnels Communication](https://github.com/SigmaHQ/sigma/blob/ab2fb3642611988012a1ee79b056e2f3068059aa/rules/windows/dns_query/dns_query_win_devtunnels_communication.yml)
- [MITRE ATT&CK - T1547.001: Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [MSAL Documentation - Microsoft Authentication Library](https://learn.microsoft.com/en-us/azure/active-directory/develop/msal-overview)

## Detection Logic
- Monitors `DeviceRegistryEvents` where:
  - The `RegistryKey` contains "inprocserver32", and
  - The `RegistryValueData` contains "msalruntime."

## Tags
- Registry Events
- COM Hijacking
- Persistence Mechanisms
- Windows Registry Monitoring
- Malicious DLL Injection
- MSAL Runtime Abuse

## Search Query
```kql
DeviceRegistryEvents
| where RegistryKey contains "inprocserver32"
| where RegistryValueData contains "msalruntime"
```
