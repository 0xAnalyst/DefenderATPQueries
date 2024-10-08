# Rule : Detection of ADFind Command Usage

## Description
This detection rule identifies suspicious use of `ADFind`, a command-line Active Directory query tool commonly leveraged by attackers for reconnaissance. Adversaries may use ADFind to extract valuable Active Directory data, such as domain information, user and group lists, or trust relationships. Monitoring for specific patterns in process command lines can help detect unauthorized ADFind activities and provide early warning of potential lateral movement or privilege escalation attempts.

This rule monitors for the execution of ADFind commands, especially those containing sensitive keywords such as `"objectcategory"`, `"domainlist"`, `"adinfo"`, `"trustdmp"`, and others that indicate potential misuse for domain enumeration or privilege escalation.

- [Elastic Security: AdFind Command Activity](https://www.elastic.co/guide/en/security/current/adfind-command-activity.html)

## Detection Logic
- Monitors `DeviceProcessEvents` for events where:
  - The `ProcessCommandLine` contains keywords related to ADFind command usage.
  - The `ProcessCommandLine` matches a regular expression pattern indicating piping or redirection, which may suggest an attempt to manipulate or exfiltrate the gathered data.

## Tags
- Active Directory Reconnaissance
- ADFind
- Domain Enumeration
- Lateral Movement
- Suspicious Command-Line Activity
- Threat Detection

## Search Query
```kql
let commandline = dynamic(["objectcategory","domainlist","dcmodes","adinfo","trustdmp","computers_pwdnotreqd","Domain Admins", "objectcategory=*"]);
DeviceProcessEvents
| where ProcessCommandLine  has_any (commandline)
| where ProcessCommandLine matches regex "(.*)>(.*)"
```
