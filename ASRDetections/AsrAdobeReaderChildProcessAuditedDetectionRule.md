# Rule : Detection of Adobe Reader Child Processes throug ASR

## Description
This detection rule identifies child processes spawned by Adobe Reader that have been audited by Advanced Security Rules (ASR). Monitoring for child processes created by Adobe Reader is important because malicious actors can exploit vulnerabilities or use malicious PDFs to launch additional processes, executing malicious payloads. This rule focuses on identifying potentially suspicious activities initiated by Adobe Reader, providing early detection of possible threats.

This rule helps identify and audit unusual child processes initiated by Adobe Reader, serving as an early warning for potential malicious activities.

## Detection Logic
- Monitors `DeviceEvents` for events where:
  - The `ActionType` is "AsrAdobeReaderChildProcessAudited".

## Tags
- Adobe Reader
- Child Processes
- PDF Security
- Malware
- Advanced Security Rules (ASR)
- Suspicious Activity

## Search Query
```kql
DeviceEvents
| where ActionType == "AsrAdobeReaderChildProcessAudited"
```
