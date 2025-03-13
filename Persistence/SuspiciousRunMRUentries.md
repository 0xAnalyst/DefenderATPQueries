# Rule : Detection of Suspicious RunMRU Registry Modifications Related to info Stealers

## Description
This detection rule identifies suspicious modifications to the **RunMRU** registry key, which stores a history of commands executed via the Windows **Run Dialog** (`Win + R`). Adversaries, including those deploying **Lumma Stealer**, may use this technique to execute malicious commands, download payloads, or establish persistence by leveraging commonly abused executables like **PowerShell, cmd.exe, rundll32.exe, and pwsh**.

As observed in **Lumma Stealer** campaigns, attackers may use **CAPTCHA-based evasion** techniques to distribute malware and execute commands that interact with malicious infrastructure via `iwr`, `https`, and `iex` in PowerShell. Monitoring changes to the **RunMRU** registry key helps detect malicious activity attempting to execute unauthorized commands or establish persistence through registry manipulation.

- [Lumma Stealer Analysis - Medium](https://medium.com/@shaherzakaria8/downloading-trojan-lumma-infostealer-through-capatcha-1f25255a0e71)

## Detection Logic
- **Monitors `DeviceRegistryEvents`** where:
  - The `RegistryKey` contains `"RunMRU"` (indicating execution history manipulation).
  - The `RegistryValueData` contains **potentially malicious command-line keywords**, such as:
    - `"powershell"` – PowerShell execution
    - `"pwsh"` – PowerShell Core execution
    - `"iwr"` – Invoke-WebRequest (used for downloading files)
    - `"https"` – Suspicious external network access
    - `"iex"` – Invoke-Expression (often abused in PowerShell attacks)
    - `"cmd.exe"` – Execution via the command prompt
    - `"rundll"` – DLL execution

## Tags
- Malware Persistence
- Registry Modification
- Windows Run Dialog Abuse
- Command Execution
- Malicious Script Execution
- Suspicious Activity
- InfoStealers

## Search Query
```kql
DeviceRegistryEvents 
| where RegistryKey contains "Runmru" 
| where RegistryValueData has_any("powershell", "iwr", "https", "iex", "cmd.exe", "rundll", "pwsh")
```
