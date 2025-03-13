# Rule : Detection of Cloudflared Argo Tunnel Communication

## Description
This detection rule identifies network communication to **Cloudflared Argo Tunnel services**, specifically targeting `trycloudflare` and `argotunnel.com` domains. Cloudflared is a legitimate tool used to securely tunnel traffic through Cloudflare's network, often for web applications and remote access. However, adversaries can **abuse Argo Tunnels to bypass network security controls**, establish covert communication channels, and exfiltrate data without detection.

This rule helps detect potential misuse of Cloudflared tunneling services by monitoring outbound DNS queries to `trycloudflare` and `argotunnel.com`.

- [Sigma Rule: DNS Query for Cloudflared Communication](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/dns_query/dns_query_win_cloudflared_communication.yml)

## Detection Logic
- Monitors `DeviceNetworkEvents` for DNS queries or network requests where:
  - The `RemoteUrl` contains `"trycloudflare"` or `"argotunnel.com"`.

## Tags
- Cloudflare Argo Tunneling
- DNS Query Monitoring
- Suspicious Network Traffic
- Covert Communication
- Data Exfiltration

## Search Query
```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("trycloudflare", "argotunnel.com")
```
