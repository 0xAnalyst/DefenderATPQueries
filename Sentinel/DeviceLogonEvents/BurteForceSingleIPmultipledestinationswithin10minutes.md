# Rule Documentation: Brute Force Logon Attempt from Single Source IP Across Multiple Devices

## Description
This detection rule identifies a potential **brute force attack** originating from a single external IP address (`RemoteIP`) that has failed to log in across **multiple Windows devices** within a short period of time. This behavior is indicative of credential stuffing or brute force login attempts, where an attacker systematically tries different combinations of usernames and passwords to gain access.

The detection is triggered when **10 or more failed logon attempts** occur from the **same Remote IP address** across **10 or more distinct devices** within a **10-minute window**. This type of activity could represent early-stage reconnaissance or lateral movement attempts after an initial foothold.

This logic is based on the behavior described in Elastic’s prebuilt rule:
- [Elastic Rule: Multiple Logon Failures from the Same Source IP](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/credential_access_bruteforce_multiple_logon_failure_same_srcip)

## Detection Logic
- **Source Table:** `DeviceLogonEvents`
- **Filters Applied:**
  - `ActionType` is `"LogonFailed"`
  - `RemoteIP` is **not empty** and **not equal to localhost (`127.0.0.1`)**
- **Aggregation Window:** 10 minutes
- **Conditions:**
  - `FailedLogonCount >= 10`
  - `DistinctTargetDevices >= 10`

## Tags
- Brute Force
- Credential Access
- Initial Access
- Logon Failures
- Suspicious Authentication Behavior
- T1110

## Search Query
```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and isnotempty(RemoteIP)
| where RemoteIP != @"127.0.0.1"
| summarize 
    FailedLogonCount = count(),
    DistinctTargetDevices = dcount(DeviceName),
    TargetDevices = make_set(DeviceName, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
  by RemoteIP, bin(Timestamp, 10m)
| where FailedLogonCount >= 10 and DistinctTargetDevices >= 10
| project 
    FirstSeen,
    LastSeen,
    RemoteIP,
    FailedLogonCount,
    DistinctTargetDevices,
    TargetDevices
| order by FailedLogonCount desc
