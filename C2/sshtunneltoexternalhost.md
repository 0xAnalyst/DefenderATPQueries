# Rule Documentation: SSH Reverse Tunnel Established to External Host

## Description
Detects SSH reverse tunneling or remote port forwarding to external hosts, which attackers use to create persistent command-and-control channels or pivot through an internal host to external infrastructure.

- **Source:** The DFIR Report — From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira (Aug 05, 2025)

## Detection Logic
- Monitor outbound `ssh` process creation with remote forwarding flags (`-R`, `-L`) or unusual port numbers.
- Alert on internal hosts initiating SSH connections to external IPs with remote port binds (e.g., `ssh -R *:10400`).
- Correlate with newly installed remote access tools or suspicious user accounts.

## Tags
- Command and Control  
- Lateral Movement  
- MITRE ATT&CK: T1572 (Protocol Tunneling), T1040 (Network Sniffing)

## Search Query
```kql
DeviceProcessEvents
| where FileName =~ "ssh.exe" or ProcessCommandLine contains "ssh "
| where ProcessCommandLine contains "-R" or ProcessCommandLine contains "-L" or ProcessCommandLine contains "RemoteForward"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, ReportId
```

## Note
This rule is very noisy and will generate a lot of alerts it needs to be adjusted to remove any legitimate behavior 
