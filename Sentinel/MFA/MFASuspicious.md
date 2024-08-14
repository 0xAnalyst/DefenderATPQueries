# Rule : User Reported MFA Suspicious Activity

## Description
This detection rule identifies and correlates suspicious user management activities within Azure Active Directory (AAD) audit logs with sign-in logs to provide a comprehensive overview of potential unauthorized access. This rule is particularly focused on operations that deviate from normal user management activities, such as those that are not associated with updating user profiles, and that contain terms indicative of reported activities.

Azure AD provides functionality for reporting suspicious activity, helping administrators to investigate and mitigate potential security threats. This rule leverages similar principles by flagging and investigating user management operations that could indicate malicious intent, such as attempts to change user information after unauthorized access.

By cross-referencing these user management events with corresponding sign-in logs, this rule helps to identify potentially compromised accounts and provides the necessary details, such as the IP address and the time of the related sign-in event, to facilitate a thorough investigation.

- [Microsoft Tech Community on Reporting Suspicious Activity](https://techcommunity.microsoft.com/t5/microsoft-entra/report-suspicious-activity-preview/m-p/3751886)

## Detection Logic
- Monitors `AuditLogs` for suspicious user management activities where:
  - The `Category` is `"UserManagement"`,
  - The `ActivityDisplayName` is not `"Update user"`,
  - The `OperationName` contains `"reported"`.
- Correlates these activities with `SigninLogs` based on the username to include information such as IP addresses and timestamps of the associated sign-ins.

## Tags
- User Management
- Account Compromise
- Azure Active Directory
- Suspicious Activity
- Audit Logs
- Sign-In Logs
- Security Investigation

## Search Query
```kql
AuditLogs
| where Category == "UserManagement"
| where ActivityDisplayName <> "Update user"
| where OperationName contains "reported"
| extend username = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| join kind=inner (
    // Get sign-in logs that match the username
    SigninLogs
    | extend username = UserPrincipalName
    | project username, IPAddress, TimeGenerated
) on username
| distinct TimeGenerated, username, ActivityDisplayName, OperationName, IPAddress

Note:
This might not report activities where IP addresses weren't in signinlogs. first part of the query can be used as a detection rule by itself
