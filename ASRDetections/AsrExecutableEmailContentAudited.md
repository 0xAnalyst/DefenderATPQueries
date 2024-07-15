# Rule :Detection of Executable Email Content Using AsrExecutableEmailContentAudited ASR rule

## Description
This detection rule identifies audited events where executable content in emails is detected, excluding files with a ".js" extension. Monitoring for executable email content is essential to identify potential phishing or malware delivery attempts via email. JavaScript files are common vectors for malicious content, but this rule focuses on other executable files that could indicate an attempt to bypass email security measures.

This rule monitors for audited actions related to executable content in email attachments, helping to identify potentially malicious files that could compromise the system.

## Detection Logic
- Monitors `DeviceEvents` for events where:
  - The `ActionType` is "AsrExecutableEmailContentAudited".
  - The `FileName` does not end with ".js".

## Tags
- Email Security
- Executable Content
- Phishing
- Malware
- Suspicious Activity

## Search Query
```kql
DeviceEvents
| where ActionType == "AsrExecutableEmailContentAudited"
| where FileName !endswith ".js"
