# Rule Documentation: Thunderbird rnpkeys.exe DLL Hijacking - StealC InfoStealer

## Description
This detection rule identifies the execution of `rnpkeys.exe` associated with the Thunderbird email client. The `rnpkeys.exe` process is related to the handling of cryptographic keys in Thunderbird. Monitoring this process is essential because it could be exploited by malicious actors to manipulate encryption keys, potentially compromising secure communications. According to the MITRE ATT&CK framework, such manipulations fall under "DLL Search Order Hijacking" (T1574.001), where adversaries may exploit the search order to load malicious DLLs.

This rule helps detect and audit the usage of `rnpkeys.exe` within Thunderbird, ensuring that only legitimate key operations are performed and providing an early warning for potential malicious activities.

- [MITRE ATT&CK: DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/)

## Detection Logic
### DeviceProcessEvents
- Monitors `DeviceProcessEvents` for events where:
  - The `FileName` contains "rnpkeys.exe".
  - The `ProcessVersionInfoProductName` is "Thunderbird".

### DeviceImageLoadEvents
- Monitors `DeviceImageLoadEvents` for events where:
  - The `InitiatingProcessFileName` contains "rnpkeys.exe".

## Tags
- Thunderbird
- Cryptographic Keys
- rnpkeys.exe
- Email Security
- Process Monitoring
- DLL Search Order Hijacking
- MITRE ATT&CK T1574.001
- Suspicious Activity

## Search Query
```kql
DeviceProcessEvents
| where FileName contains "rnpkeys.exe"
| where ProcessVersionInfoProductName == "Thunderbird"
```
```kql
DeviceImageLoadEvents
| where InitiatingProcessFileName contains "rnpkeys.exe"
```
