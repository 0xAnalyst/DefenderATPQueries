---
title: Suspicious Pod or Container Shell Execution
tags:
  - Execution
  - Persistence
  - Privilege Escalation
  - Containers
references:
  - https://github.com/elastic/detection-rules/commit/f098336ff951dd7c2b78ae67054ad517c846e671
files: []
---

Detects suspicious use of container or Kubernetes administration tooling to spawn an interactive shell with command-line patterns commonly observed during post-exploitation activity.

## Description

Threat actors frequently abuse legitimate container administration utilities such as `kubectl`, `docker`, or `nerdctl` to gain interactive access inside a pod or container. Instead of deploying standard workloads, attackers often launch a shell directly and execute one-liner commands to establish persistence, stage payloads, or open reverse shells.

This technique is commonly observed following stolen Kubernetes credentials, exposed cluster APIs, or compromised CI/CD runners.

## Detection Logic

This detection identifies process execution where:

- A container or Kubernetes administration binary is used
- A shell interpreter is executed as part of container or pod creation
- The command-line contains indicators associated with persistence, credential manipulation, payload staging, or remote command execution

## Defender Advanced Hunting

```kql
let Shells = dynamic(["bash","dash","sh","tcsh","csh","zsh","ksh","fish"]);
let Launchers = dynamic(["kubectl","docker","nerdctl","ctl"]);
let Suspicious = dynamic([
  "atd","cron",
  "/etc/rc.local","/dev/tcp/","/etc/init.d","/etc/update-motd.d","/etc/ld.so","/etc/sudoers",
  "base64 ","/etc/profile","/etc/ssh","/.ssh/","/root/.ssh","~/.ssh/",
  "autostart","xxd ","/etc/shadow","./.",
  "import pty","pty.spawn","import subprocess","subprocess.call",
  "TCPSocket.new","TCPSocket.open","io.popen","os.execute","fsockopen",
  "disown"," ncat "," nc "," netcat "," nc.traditional ","socat","telnet",
  "/tmp/","/dev/shm/","/var/tmp/",
  "/boot/","/sys/","/lost+found/","/media/","/proc/",
  "/var/backups/","/var/log/","/var/mail/","/var/spool/"
]);

DeviceProcessEvents
| where FileName in~ (Launchers)
| where ProcessCommandLine has "run"
| where ProcessCommandLine has_any (Shells)
| where ProcessCommandLine has_any (Suspicious)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath,
    ProcessId,
    InitiatingProcessId,
    ReportId
| order by Timestamp desc
```
