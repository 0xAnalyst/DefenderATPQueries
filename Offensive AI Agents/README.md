# Offensive AI Agents - Hunting Queries

## Description
This folder contains Microsoft Defender XDR hunting queries for **agentic offensive frameworks** — ARTEX, PentAGI, CAIRN, Hexstrike and similar tools where an LLM-driven agent plans and runs the attack. The rules focus on behaviors that span attack stages (discovery → permission probing → credential access → webshell → webhook egress) rather than trying to prove that an AI was involved. No query can identify an AI agent with certainty.

- **Source:** Google Threat Intelligence Group / Mandiant — [ARTEX and Friends: Enter Agentic Offensive Frameworks](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks) (Oct 30, 2026)

The report documents ARTEX artifacts and behaviors including `artex-probe-*` / `ArtexProbe` files, rotating `webhook.site` endpoints, aggressive cloud permission probing, SQL-to-JSP webshell attempts and automated AD discovery. Rules marked **Report-documented** in their Provenance line map directly to those findings. The others are **defender-authored behavioral extrapolations**, not published Google detection signatures.

## Rules
| ID | Rule | Severity | Tables | MITRE ATT&CK |
|---|---|---|---|---|
| OAI-001 | [ARTEX-like Incremental Probe Artifacts](Execution_ARTEX_Probe_Artifacts.md) | High | `DeviceFileEvents, DeviceProcessEvents` | T1036 |
| OAI-002 | [Unusually Fast Process Bursts with Diverse Commands](Execution_Rapid_Process_Bursts.md) | Medium | `DeviceProcessEvents` | T1059 |
| OAI-003 | [Command-Output Transfer to Webhooks](Exfiltration_Webhook_Command_Output.md) | High | `DeviceProcessEvents, DeviceNetworkEvents` | T1041 |
| OAI-004 | [Multiple Unique Webhook Endpoints Contacted by One Device](Exfiltration_Rotating_Webhook_Destinations.md) | High | `DeviceProcessEvents, DeviceNetworkEvents` | T1041 |
| OAI-005 | [Rapid AD Reconnaissance Utility and Script Invocation](Discovery_Automated_AD_Recon.md) | High | `DeviceProcessEvents` | T1087 |
| OAI-006 | [Potential Kerberoasting and DCSync Command Patterns](CredentialAccess_Kerberoast_DCSync_Commands.md) | High | `DeviceProcessEvents` | T1558.003, T1003.006 |
| OAI-007 | [Web Executable File Written by Server and Database Process](Persistence_Webshell_File_Drop.md) | High | `DeviceFileEvents` | T1505.003 |
| OAI-008 | [MySQL General-Log Poisoning via Process-Visible SQL Strings](Persistence_MySQL_JSP_Log_Poisoning.md) | High | `DeviceProcessEvents` | T1505.003 |
| OAI-009 | [Azure CLI Permission and Storage Testing Burst](Discovery_Azure_CLI_Permission_Probing.md) | Medium | `DeviceProcessEvents` | T1526 |
| OAI-010 | [AWS CLI Permission Dry Runs and Metadata Probes](Discovery_AWS_CLI_Permission_Probing.md) | Medium | `DeviceProcessEvents` | T1526 |
| OAI-011 | [Rapid East-West Port and Host Scanning](Discovery_Internal_Network_Sweep.md) | High | `DeviceNetworkEvents` | T1046 |
| OAI-012 | [New External FQDNs Contacted by Workload](C2_New_External_Destinations.md) | Medium | `DeviceNetworkEvents` | T1071.001 |
| OAI-013 | [Unusual Cloud Application API Activity Burst](Discovery_CloudApp_High_Velocity_Activity.md) | Medium | `CloudAppEvents` | T1087 |
| OAI-014 | [Cloud Object Read/Download Bursts](Collection_CloudApp_Object_Download_Burst.md) | Medium | `CloudAppEvents` | T1530 |
| OAI-015 | [AD Reconnaissance Followed by Webhook Egress on the Same Device](Correlation_AD_Recon_Then_Webhook_Egress.md) | High | `DeviceProcessEvents, DeviceNetworkEvents` | T1087, T1041 |
| OAI-016 | [Multiple Distinct Scripted Command Variations in a Short Window](Execution_Script_Retry_Variations.md) | Medium | `DeviceProcessEvents` | T1059 |
| OAI-017 | [Kudu SCM API and Remote Execution Visible in Process Command Lines](Execution_Kudu_SCM_Remote_Commands.md) | High | `DeviceProcessEvents` | T1059 |
| OAI-018 | [OAST, Webhook, and Disposable Callback Destinations](C2_OAST_Webhook_Callback_Domains.md) | Medium | `DeviceNetworkEvents` | T1071.001 |

## Detection Logic
- **Framework artifacts:** probe file names and command lines (OAI-001).
- **Machine-speed tempo:** bursts of diverse commands and rapid retry variations (OAI-002, OAI-016).
- **Webhook / OAST egress:** command output posted to `webhook.site` and other callback services (OAI-003, OAI-004, OAI-018).
- **AD discovery and credential access:** AD enumeration bursts, Kerberoasting and DCSync tooling (OAI-005, OAI-006).
- **Webshell placement:** web-executable files written by server/DB processes and MySQL general-log poisoning (OAI-007, OAI-008).
- **Cloud permission probing:** Azure and AWS CLI validate / dry-run / list-keys bursts, Kudu SCM API use (OAI-009, OAI-010, OAI-017).
- **Network and SaaS behavior:** east-west scanning, new external destinations, CloudAppEvents bursts (OAI-011 to OAI-014).
- **Correlation:** AD recon followed by webhook egress on the same device (OAI-015) — the strongest signal in the folder.

## Tags
- Agentic Offense
- ARTEX
- Offensive AI
- Behavioral Hunting
- Microsoft Defender XDR

## How to Use
1. Open **Microsoft Defender > Hunting > Advanced hunting**.
2. Copy the query from one rule, run it against your own telemetry, and confirm the tables and columns exist in your tenant.
3. Review benign automation, developer tools, penetration tests, scanners and admin accounts before changing thresholds.
4. Start as a hunt. Promote only validated high-signal rules to custom detections — summarized queries need reshaping to return `Timestamp`, `ReportId` and entity columns.
5. Run each rule **on its own**. They are not meant to be combined into one script.

## Coverage Boundaries
- **Endpoint only:** `Device*` tables see behavior on onboarded devices, not Internet-originated attacks against your web/API services. Request fuzzing, 200/403 probing and server-side SQL abuse need WAF, reverse proxy, IIS/NGINX, application and SQL audit logs in Sentinel or another SIEM.
- **Cloud plane:** `CloudAppEvents` covers connected SaaS apps, not full Azure ARM or AWS CloudTrail. For real `DryRun`, permission probes, ARM validations and storage read/write/delete sequences, build Sentinel rules on `AzureActivity`, `StorageBlobLogs` and `AWSCloudTrail`.
- **DCSync:** command-line strings miss scriptless DRSUAPI replication. Use Defender for Identity or DC event collection.
- **Webhook URLs:** `RemoteUrl` often holds only the host, not the full path or UUID. Counting rotating endpoints properly needs HTTP proxy logs.
- **Time/volume:** agents are fast, but so is legitimate automation. Thresholds are hypotheses, not vetted alert criteria.
- **KQL dialect:** queries use Defender XDR Advanced Hunting schema. Sentinel Log Analytics schemas differ — do not paste directly into Sentinel analytics rules.
- **Licensing:** `Device*` tables need Defender for Endpoint; `CloudAppEvents` needs Defender for Cloud Apps with connected apps.

## Triage Steps
1. **Validate authorization:** approved red team, vulnerability scans, deployments, IT scripts, test webhooks.
2. **Establish entry point:** first sign-in / source IP, compromised web or API, Kudu/SCM interface, service principal token.
3. **Reconstruct velocity:** count distinct commands/events in 30s, 1m and 5m windows; look at clusters separated by pauses.
4. **Reconstruct sequence:** discovery → permission probe → lateral movement → execution → data access → webhook or unfamiliar egress.
5. **Identity and scope:** impacted hosts, Azure/AWS subscriptions, service principals, AD groups, object reads, new accounts and credentials.
6. **Contain per approved IR policy:** revoke sessions/tokens, isolate hosts, restrict egress, rotate secrets, review persistence.
7. **Preserve evidence:** UTC timeline, event IDs, raw logs, files/hashes, process trees and proxy paths.

## False Positive Tuning
- **Phase 1:** run daily as hunts for 2 weeks and record trusted automations.
- **Phase 2:** focus on high-value cohorts (servers, DMZ, domain controllers); exclude signed/approved scanners only with documented owners.
- **Phase 3:** promote high-confidence rules to custom detections after adding entity IDs and unaggregated timestamps, and validating alert volume.
- For `CloudAppEvents`, check real action names first: `CloudAppEvents | summarize count() by Application, ActionType | top 100 by count_`.
- Keep tenant-specific exclusions out of the shared rules.

## Sentinel Extension (not included as queries)
Build separate, schema-verified analytics rules on:
- **AzureActivity** — bursts of `Microsoft.Resources/deployments/validate/action`, role assignments and `listKeys`, correlated by `Caller`, source IP and correlation ID.
- **StorageBlobLogs** — write/read/delete cycles on new blobs, mass reads, unfamiliar identity or IP.
- **AWSCloudTrail** — `DryRun` / `UnauthorizedOperation`, IAM permission testing, `RunInstances`, `CreateVolume`, `DescribeSnapshots`.
- **WAF / application / SQL audit** — status-code oscillation, excessive 403/404, `general_log_file`, repeated JSP webshell attempts.
- **Entra sign-in and service principal sign-in logs** — first-seen ASN/IP/region followed quickly by control-plane enumeration and data access.

## Note
Research-grade starter pack; **not yet tested in a live Defender tenant**. Confirm syntax, columns, action types and custom detection requirements before production use. Do not label a case "AI agent confirmed" without independent evidence such as framework artifacts or operator logs — behavior supports a hypothesis, not attribution.
