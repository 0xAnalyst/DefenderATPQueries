# Rule : Rapid AD Reconnaissance Utility and Script Invocation

## Description
Detects bursts of Active Directory enumeration commands — `nltest`, `dsquery`, `setspn`, `net group "Domain Admins"`, `AdFind`, `ldapsearch` and the `Get-AD*` PowerShell cmdlets. The report describes ARTEX performing automated AD discovery; an agent typically walks through trusts, DCs, users, groups and SPNs in rapid succession.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-005
- **Severity:** High (initial suggestion; tune before alerting)
- **Provenance:** Report-documented behavior

## Detection Logic
- Filters `DeviceProcessEvents` to AD discovery binaries and PowerShell.
- Requires AD-discovery keywords in the command line (`/domain_trusts`, `/dclist`, `Domain Admins`, `Get-ADUser`, `Get-ADTrust`, `setspn`, ...).
- Alerts on **≥ 6 commands** with **≥ 4 distinct command lines** in a 5-minute window.

## Relevant Tables
- `DeviceProcessEvents`

## Tags
- Agentic Offense
- ARTEX
- Discovery
- Active Directory
- MITRE ATT&CK: T1087 (Account Discovery)

## Search Query
```kql
let lookback=24h;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("nltest.exe","dsquery.exe","setspn.exe","net.exe","net1.exe","whoami.exe","adfind.exe","ldapsearch","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("/domain_trusts","/dclist","/all_trusts","Domain Admins","Get-ADUser","Get-ADComputer","Get-ADGroup","Get-ADTrust","Get-ADServiceAccount","Get-ADObject","Get-ADForest","Get-ADDomain","Get-ADDefaultDomainPasswordPolicy","setspn","dsquery","ldapsearch","/domain")
| summarize Commands=count(), DistinctQueries=dcount(ProcessCommandLine), Tools=make_set(FileName,8), Examples=make_set(substring(ProcessCommandLine,0,200),8), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceId, DeviceName, AccountName, bin(Timestamp,5m)
| where Commands >= 6 and DistinctQueries >= 4
| order by Commands desc
```

## False Positive Tuning
- IT inventory and identity administration.
- Exclude identity-admin jump hosts and IT inventory scripts by device and account.

## Triage Steps
1. Review the command sequence for trust / DC / privileged group enumeration.
2. Check for Kerberoasting or DCSync follow-up (OAI-006) and webhook egress (OAI-015).

## Note
PowerShell script block activity may not appear in process arguments. Thresholds are starting points, not validated defaults — run as a hunt first.
