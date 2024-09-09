# Rule : Visual Studio Code Tunnel Abuse Detection

## Description
This detection rule identifies suspicious use of the "tunnel" feature within Visual Studio Code (VSCode) that could indicate malicious activity or abuse. Attackers may leverage VSCode's tunnel functionality to establish unauthorized connections and bypass network restrictions. The rule monitors for command lines associated with tunnel creation, host setup, and allowing anonymous access. Malicious actors can exploit these functionalities to exfiltrate data or maintain persistence in a network.

This method has been observed in espionage campaigns such as **Stately Taurus**, which targeted organizations in Southeast Asia, highlighting the growing abuse of legitimate tools like VSCode in advanced attacks.

- [Stately Taurus Campaign by Unit42](https://unit42.paloaltonetworks.com/stately-taurus-abuses-vscode-southeast-asian-espionage/)

## Detection Logic
- Monitors `DeviceProcessEvents` where:
  - The `ProcessVersionInfoProductName` is "Visual Studio Code" and the `ProcessCommandLine` contains "tunnel".
  - The `ProcessCommandLine` includes:
    - "host" and "allow-anonymous"
    - "port" and "create" with a `-p` flag for specifying ports

## Tags
- Process Execution
- Tunneling
- DevTunnels
- Visual Studio Code
- Espionage

## Search Query
```kql
DeviceProcessEvents
| where (ProcessVersionInfoProductName == @"Visual Studio Code" and ProcessCommandLine contains "tunnel" )
or ProcessCommandLine has_all ("host", "allow-anonymous") 
or ProcessCommandLine has_all ("port", "create", "-p")
```
