# Rule: Linux Webshell Indicators

## Description
Detects potential webshell activity by monitoring process events where suspicious processes associated with web servers and common system administration tools are executed.

- Source: [Sigma rule for Linux webshell detection](https://github.com/SigmaHQ/sigma/blob/0bb6f0c0d75ae3e1c37f9ab77d68f20cdb32ecd3/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml)

## Detection Logic
- Filters events to include process executions where:
  - Initiating process filenames include common web server executables (`httpd`, `lighttpd`, `nginx`, `apache2`, `node`, `caddy`).
  - Executed file names include common system administration tools (`whoami`, `ifconfig`, `ip`, `uname`, `cat`, `crontab`, `hostname`, `iptables`, `netstat`, `pwd`, `route`).
- Excludes events where:
  - The initiating process filename is `calico-node`.
  - The process command line includes `cat /proc/cpuinfo`.

## Tags
- Webshell Detection
- Process Events
- Linux

## Search Query
```kql
DeviceProcessEvents
| where InitiatingProcessFileName has_any ("httpd", "lighttpd", "nginx", "apache2", "node", "caddy")
| where FileName has_any ("whoami", "ifconfig", "ip", "uname", "cat", "crontab", "hostname", "iptables", "netstat", "pwd", "route")
| where InitiatingProcessFileName !contains "calico-node"
| where ProcessCommandLine !contains "cat /proc/cpuinfo"
