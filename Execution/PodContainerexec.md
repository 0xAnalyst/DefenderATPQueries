# Rule: Suspicious Pod or Container Creation with Shell Execution

## Description
This detection rule identifies suspicious creation of **containers or Kubernetes pods** that immediately execute an interactive shell (`bash`, `sh`, `zsh`, etc.) with command-line patterns commonly associated with **persistence**, **privilege escalation**, or **remote command execution**.

Adversaries frequently abuse legitimate container administration tools such as `kubectl`, `docker`, or `nerdctl` to deploy short-lived pods or containers that run a malicious one-liner shell command. These commands are often used to:
- establish persistence via `cron`, `at`, or startup scripts
- modify sensitive system files such as `sudoers`, `shadow`, or SSH keys
- stage payloads using `base64` or `xxd`
- create reverse shells using `/dev/tcp`, `nc`, `socat`, or `telnet`
- write artifacts into temporary or uncommon filesystem locations

Monitoring container creation followed by suspicious shell execution provides early visibility into post-exploitation activity in containerized and Kubernetes environments.

- **Elastic Detection Rule (same logic):**
  https://github.com/elastic/detection-rules/blob/main/rules/linux/execution_suspicious_pod_or_container_creation_command_execution.toml

## Detection Logic
- Monitors Linux process execution telemetry for container or pod creation commands.
- Detects use of container administration tools (`kubectl`, `docker`, `nerdctl`, `ctl`) invoking `run`.
- Flags cases where a shell is executed with suspicious command-line indicators related to persistence, credential access, or network-based command execution.

## Tags
- Linux Security
- Containers
- Kubernetes
- Execution
- Persistence
- Privilege Escalation
- Suspicious Command Line
- Living-off-the-Land

## Search Query
```kql
let Shells = dynamic(["bash","dash","sh","tcsh","csh","zsh","ksh","fish"]);
let Launchers = dynamic(["kubectl","docker","nerdctl","ctl"]);
let Suspicious = dynamic([
  "atd","cron",
  "/etc/rc.local",
  "/dev/tcp/",
  "/etc/init.d",
  "/etc/update-motd.d",
  "/etc/ld.so",
  "/etc/sudoers",
  "base64 ",
  "/etc/profile",
  "/etc/ssh",
  "/.ssh/",
  "/root/.ssh",
  "~/.ssh/",
  "autostart",
  "xxd ",
  "/etc/shadow",
  "./.",
  "import pty","pty.spawn",
  "import subprocess","subprocess.call",
  "TCPSocket.new","TCPSocket.open",
  "io.popen","os.execute","fsockopen",
  "disown",
  " ncat "," nc "," netcat "," nc.traditional ",
  "socat","telnet",
  "/tmp/","/dev/shm/","/var/tmp/",
  "/boot/","/sys/","/lost+found/","/media/","/proc/",
  "/var/backups/","/var/lo
```
