# Rule : Unusually Fast Process Bursts with Diverse Commands

## Description
Detects machine-speed bursts of shell, scripting, discovery and cloud CLI executions from a single account on a single device. Agentic frameworks issue many distinct commands per minute as the model plans, runs and re-plans — a tempo that is unusual for an interactive human operator. This is an inference about speed and variety, not proof of AI involvement.

- **Source:** Google Threat Intelligence Group / Mandiant — ARTEX and Friends: Enter Agentic Offensive Frameworks (Oct 30, 2026) — https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- **Rule ID:** OAI-002
- **Severity:** Medium (initial suggestion; tune before alerting)
- **Provenance:** Defender-authored behavioral extrapolation

## Detection Logic
- Filters `DeviceProcessEvents` to shells, interpreters, discovery tools and cloud CLIs (`powershell`, `cmd`, `curl`, `python`, `bash`, `net`, `whoami`, `nltest`, `dsquery`, `ldapsearch`, `aws`, `az`).
- Buckets activity into 1-minute windows per device and account.
- Alerts when a window has **≥ 12 executions**, **≥ 3 distinct tools** and **≥ 8 distinct command lines**.

## Relevant Tables
- `DeviceProcessEvents`

## Tags
- Agentic Offense
- Execution
- Behavioral
- Velocity
- MITRE ATT&CK: T1059 (Command and Scripting Interpreter)

## Search Query
```kql
let lookback = 24h;
let window = 1m;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","curl.exe","python.exe","python3","bash","sh","net.exe","net1.exe","whoami.exe","nltest.exe","dsquery.exe","ldapsearch","aws","az")
| summarize Events=count(), DistinctTools=dcount(FileName), DistinctCommands=dcount(ProcessCommandLine), Examples=make_set(strcat(FileName, ": ", substring(ProcessCommandLine,0,160)), 8), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceId, DeviceName, AccountName, bin(Timestamp,window)
| where Events >= 12 and DistinctTools >= 3 and DistinctCommands >= 8
| extend SecondsBetween= datetime_diff('second',LastSeen,FirstSeen)
| project Timestamp, DeviceId, DeviceName, AccountName, Events, DistinctTools, DistinctCommands, SecondsBetween, Examples
| order by Events desc
```

## False Positive Tuning
- Build systems, admin scripts and CI runners.
- Exclude build agents, CI runners and configuration-management service accounts.
- Tune `window` and the three thresholds to your baseline before alerting.

## Triage Steps
1. Review the `Examples` set — is it a coherent attack sequence (discovery → credential → movement) or build noise?
2. Identify the parent process launching the burst (agent runtime, Python, Node, SSH session).
3. Check whether the account normally logs on to this device.

## Note
Machine-speed process bursts are an inference, not AI attribution. Thresholds are starting points, not validated defaults — run as a hunt first.
