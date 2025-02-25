# Rule : Windows Event Log Access Tampering Via Registry modification

## Description
This detection rule identifies attempts to modify Windows registry keys associated with the Event Log service and its channels, specifically targeting keys that end with "CustomSD" or "ChannelAccess". Adversaries may alter these registry settings to disable or manipulate event logging, hindering forensic investigations and enabling persistence or further malicious activity.

By flagging registry value set actions on these keys, this rule helps detect efforts to tamper with Windows Event Log security descriptors, which is a common tactic used to evade detection.

- [Sigma Rule: Registry Set Disable Windows Event Log Access](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_disable_windows_event_log_access/)

## Detection Logic
- **Monitored Events:**  
  The rule monitors `DeviceRegistryEvents` for actions where:
  - The `RegistryKey` contains "EventLog" or "Channels".
  - The `ActionType` is "RegistryValueSet".
- **Suspicious Activity:**  
  Flags events where the `RegistryKey` ends with either "CustomSD" or "ChannelAccess", which may indicate an attempt to alter the security descriptors for event logging.

## Tags
- Registry Modification
- Event Log Tampering
- Windows Security
- Persistence
- Evasion
- Malicious Activity

## Search Query
```kql
DeviceRegistryEvents
| where RegistryKey has_any ("EventLog", "Channels") and ActionType == "RegistryValueSet"
| where RegistryKey endswith "CustomSD" or RegistryKey endswith "ChannelAccess"
```
