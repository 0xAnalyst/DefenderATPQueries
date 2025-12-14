---
title: Suspicious Pod or Container Shell Execution
tags:
  - Containers
  - Kubernetes
  - Execution
  - Persistence
  - Privilege Escalation
references:
  - https://github.com/elastic/detection-rules/commit/f098336ff951dd7c2b78ae67054ad517c846e671
files: []
---

Detects suspicious container or pod execution where administrative tooling (`kubectl`, `docker`, `nerdctl`) is used to launch an interactive shell with command-line patterns commonly observed during post-exploitation activity.

---

## Description

Threat actors abusing Kubernetes or containerized environments often rely on legitimate administration tools to gain execution inside a cluster. Instead of deploying standard workloads, attackers commonly spawn a container or pod and immediately execute a shell (`bash`, `sh`, `zsh`) to perform hands-on operations.

Once inside the container, attackers may establish persistence, manipulate authentication material, stage payloads, or open reverse shells. This activity frequently blends in with legitimate DevOps operations and is therefore easy to miss without command-line level inspection.

---

## Detection Logic

This detection identifies:

- Container or Kubernetes administration tooling used to create or run a pod/container
- Immediate execution of a shell interpreter
- Presence of suspicious command-line indicators associated with:
  - Persistence (`cron`, `at`, `rc.local`)
  - Privilege escalation (`/etc/sudoers`, `/etc/shadow`)
  - Credential access (SSH key paths)
  - Payload staging (`base64`, `xxd`)
  - Reverse shells (`/dev/tcp`, `nc`, `socat`, `telnet`)
  - Execution from temporary or sensitive directories

---

## Microsoft Defender for Endpoint

### Advanced Hunting Query

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
  "/tmp/","/dev/shm/","/var/tmp/","/boot/","/sys/","/lost+found/","/media/","/proc/",
  "/var/backups/","/var/log/","/var/mail/","/var/spool/"
]);

DeviceProcessEvents
| where FileName in~ (Launchers)
| where ProcessCommandLine has "run"
| where ProcessCommandLine has_any (Shells)
| where ProcessCommandLine has_any (Suspicious)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath,
          ProcessId, InitiatingProcessId, ReportId
| order by Timestamp desc
