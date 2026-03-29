# Rule : Node.js Blockchain C2 Communication

## Description
Detects Node.js communication with blockchain APIs used for payload delivery.

## Detection Logic
- Node network events to blockchain endpoints

## MITRE ATT&CK
- T1071 – Application Layer Protocol
- T1102 – Web Service / Blockchain C2

## Tags
Command and Control, Blockchain, Node.js

## Search Query
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where RemoteUrl has_any ("trongrid.io", "aptoslabs.com")
```

## References
- TronGrid API
- Aptos Blockchain
