# Rule : Detection of Suspicious Visual Studio DevTunnels Communication

## Description
This detection rule monitors network communications involving suspicious connections to Visual Studio DevTunnels APIs, specifically to domains ending with `tunnels.api.visualstudio.com` or `devtunnels.ms`. DevTunnels is a feature used for secure remote connections and debugging in Visual Studio. However, misuse of this service by malicious actors can lead to unauthorized remote access or data exfiltration.

This rule flags potentially suspicious traffic by excluding legitimate processes such as `ServiceHub.Host.dotnet.x64.dll` or `ServiceHub.Host.dotnet.arm64` from Visual Studio's internal services. Monitoring for unusual process interactions with these URLs can help identify potential misuse or lateral movement in a network.

- [SigmaHQ Rule for DevTunnels Communication](https://github.com/SigmaHQ/sigma/blob/ab2fb3642611988012a1ee79b056e2f3068059aa/rules/windows/dns_query/dns_query_win_devtunnels_communication.yml)

## Detection Logic
- Monitors `DeviceNetworkEvents` for events where:
  - The `RemoteUrl` ends with `tunnels.api.visualstudio.com` or `devtunnels.ms`, and
  - The initiating process is not associated with legitimate Visual Studio processes, such as `ServiceHub.Host.dotnet.x64.dll` or `ServiceHub.Host.dotnet.arm64`.

## Tags
- DevTunnels Monitoring
- Suspicious Network Traffic
- Visual Studio Security
- Remote Access Detection
- Threat Detection

## Search Query
```kql
DeviceNetworkEvents
| where RemoteUrl endswith "tunnels.api.visualstudio.com" or RemoteUrl endswith "devtunnels.ms"
| where InitiatingProcessVersionInfoOriginalFileName != @"ServiceHub.Host.dotnet.x64.dll" 
| where InitiatingProcessVersionInfoFileDescription != @"ServiceHub.Host.dotnet.arm64"
```
