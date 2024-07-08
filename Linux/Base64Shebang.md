# Rule: Base64 Encoded Shebang Detection

## Description
Identifies potential malicious scripts by detecting processes with Base64 encoded shebang lines in their command lines. Shebang lines are typically used to specify the script interpreter, and encoding them in Base64 can indicate attempts to obfuscate malicious activity.

- Source: [Sigma rule for detecting Base64 encoded shebang lines in Linux](https://github.com/SigmaHQ/sigma/blob/0bb6f0c0d75ae3e1c37f9ab77d68f20cdb32ecd3/rules/linux/process_creation/proc_creation_lnx_base64_shebang_cli.yml)

## Detection Logic
- Monitors process command lines for Base64 encoded shebang lines, which are indicative of script obfuscation. Specifically, it looks for:
  - `IyEvYmluL2Jhc2` (Base64 for `#!/bin/bash`)
  - `IyEvYmluL2Rhc2` (Base64 for `#!/bin/dash`)
  - `IyEvYmluL3pza` (Base64 for `#!/bin/zsh`)
  - `IyEvYmluL2Zpc2;IyEvYmluL3No` (Base64 for `#!/bin/fish` and `#!/bin/sh`)

## Tags
- Base64 Encoding
- Shebang Detection
- Process Events
- Linux

## Search Query
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("IyEvYmluL2Jhc2", "IyEvYmluL2Rhc2", "IyEvYmluL3pza", "IyEvYmluL2Zpc2;IyEvYmluL3No")
