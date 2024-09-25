# Rule Documentation: Suspicious PowerShell Web Requests

## Description
This detection rule is designed to identify PowerShell commands associated with downloading or transferring data from a system, often used by attackers during data exfiltration or for malicious downloads. Malicious actors use web request utilities such as `Invoke-WebRequest`, `iwr`, `wget`, `curl`, `Net.WebClient`, and `Start-BitsTransfer` within PowerShell to interact with remote resources, posing a significant threat to system security.

Detecting these commands helps flag potential data exfiltration attempts or unauthorized file transfers that could indicate malicious activity or compromise.
Sigma Rule: Suspicious Data Exfiltration via CLI https://github.com/SigmaHQ/sigma/blob/35a5eb9a4cb6f9c7a25277617806471d9999b255/rules/windows/process_creation/proc_creation_win_susp_data_exfiltration_via_cli.yml

## Detection Logic
- Filters `DeviceEvents` where the `ActionType` contains `"PowerShellCommand"`.
- Parses the `AdditionalFields` to analyze the PowerShell command executed.
- Matches the PowerShell command against suspicious web request utilities such as:
  - `Invoke-WebRequest` (iwr)
  - `wget`
  - `curl`
  - `Net.WebClient`
  - `Start-BitsTransfer`

These commands are often used to download or upload files, and their presence in command-line executions is suspicious in many scenarios, especially outside of standard administrative use.

## Tags
- PowerShell
- Data Exfiltration
- Malicious Downloads
- Suspicious Command Execution

## Search Query
```kql
DeviceEvents
| where ActionType contains "PowerShellCommand"
| extend parsed = parse_json(AdditionalFields)
| where parsed.Command matches regex @"\b(Invoke-WebRequest|iwr|wget|curl|Net\.WebClient|Start-BitsTransfer)\b"
