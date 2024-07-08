# Rule : BPF and Kprobe Tracing Detection

## Description
Detects the use of BPF (Berkeley Packet Filter) and kprobes with potentially unsafe or enabled tracing configurations. These tools are powerful for system monitoring and debugging but can also be misused for malicious purposes, such as extracting sensitive information or manipulating system behavior.

- Source: [Sigma rule for detecting BPF and kprobe tracing](https://github.com/SigmaHQ/sigma/blob/0bb6f0c0d75ae3e1c37f9ab77d68f20cdb32ecd3/rules/linux/process_creation/proc_creation_lnx_bpf_kprob_tracing_enabled.yml)

## Detection Logic
- Monitors process command lines for specific patterns indicating the use of BPF and kprobes with potentially risky configurations:
  - `bpftrace` with the `--unsafe` flag, which allows BPF trace scripts to perform potentially unsafe operations.
  - `kprobes` with `enabel`, indicating kprobe tracing is enabled.

## Tags
- BPF
- Kprobes
- Tracing Detection
- Process Events
- Linux

## Search Query
```kql
DeviceProcessEvents
| where ProcessCommandLine has_all ("bpftrace", "--unsafe") or ProcessCommandLine has_all ("kprobes", "enabel")
