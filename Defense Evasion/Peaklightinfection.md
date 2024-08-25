# Rule : Peaklight Masquerading with PowerShell and Media Player files

## Description
This detection rule identifies instances of PowerShell being executed alongside media player executables, such as `wmplayer.exe`, `setup_wm.exe`, or `Microsoft.Media.Player.exe`, as well as PowerShell executions involving `.mp4` files in the `appdata` directory. This behavior is commonly associated with stealthy, memory-only malware attacks, such as Peaklight, which leverages masquerading techniques to evade detection.

Peaklight malware is known for its ability to avoid writing files to disk by operating entirely in memory, using trusted system processes to appear legitimate. This makes detection more difficult. In this scenario, attackers abuse PowerShell to launch malware while masquerading it as media playback activity, exploiting user expectations and disguising malicious intent behind seemingly benign processes.

By leveraging this detection, security teams can identify potential malicious activity masquerading as media players and block attempts to evade traditional defenses.

- [Peaklight: Decoding Stealthy Memory-Only Malware](https://cloud.google.com/blog/topics/threat-intelligence/peaklight-decoding-stealthy-memory-only-malware)
- [Masquerading Technique T1036: Malware Peaklight Defense Evasion](https://github.com/Sam0x90/CB-Threat-Hunting/blob/789fa8c238afd02059cd1ceadcdddbd146fcbf93/Detections/Malwares%26Tools/malware_peaklight_defense_evasion_t1036_masquerading_powershell_by_opening_video_file_as_expected_by_the_user.yaml)

## Detection Logic
- Monitors `DeviceProcessEvents` for events where:
  - The `InitiatingProcessFileName` is `"powershell.exe"`, and
  - The `FileName` is `"setup_wm.exe"`, `"wmplayer.exe"`, or `"Microsoft.Media.Player.exe"`, or
  - The `ProcessCommandLine` contains both `"appdata"` and `".mp4"`.

## Tags
- Process Events
- Masquerading
- PowerShell
- Memory-Only Malware
- Defense Evasion
- Suspicious Activity

## Search Query
```kql
DeviceProcessEvents
| where InitiatingProcessFileName == "powershell.exe"  
| where FileName in ("setup_wm.exe", "wmplayer.exe", "Microsoft.Media.Player.exe")
   or (ProcessCommandLine contains "appdata" and ProcessCommandLine contains ".mp4")
