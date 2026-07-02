# Rule : Privileged Account Successful Sign-in from New ASN

## Description
That is useful for identifying suspicious admin access from a new network provider.

## Detection Logic
- Creates a list of all admin users
- creates alist of all the ASNs used by the users in past 13 days
- check if any new ASNs are there for any privilages user today which was not seen before

## Tags
- Privilege Escalation
- Suspicious Activity

## Search Query
```kql
let admins=(IdentityInfo
| where AssignedRoles contains "admin" or GroupMembership has "Admin"
| summarize by tolower(AccountUPN));
//admins
let known_asns = (
SigninLogs
| where TimeGenerated between(ago(14d)..ago(1d))
| where ResultType == 0
| summarize by AutonomousSystemNumber);
//known_asns
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| where tolower(UserPrincipalName) in (admins)
| where AutonomousSystemNumber !in (known_asns)
| project-reorder TimeGenerated, UserPrincipalName, UserAgent, IPAddress, AutonomousSystemNumber
| extend AccountName = tostring(split(UserPrincipalName, "@")[0]), AccountUPNSuffix = tostring(split(UserPrincipalName, "@")[1])
```
## References
- [SIGNINLOGS](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)