# What does ASR rules offer
ASR rules offer a broad range of built-in rules to secure your endpoint, covering areas like Office applications (think macros, DDE’s, etc.) subversion or leverage, but also things like Webmail, script, WMI, LSASS, and much more.
## To implement ASR rules following is Required:
  - Computers running Windows 10, versions 1709 and later,  Windows Server version 1803 (Semi-Annual Channel or later) and Windows Server 2019
  - Windows 10 Pro/Enterprise/Education
  - Microsoft Defender antivirus must be active (cannot be in passive mode!)
  - Some rules require cloud-delivered protection to be enabled
References https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/demystifying-attack-surface-reduction-rules-part-1/ba-p/1306420



# ASR rule name to ASR guid
| GUID                                 | ASR rule name                                                                                       |
|--------------------------------------|-----------------------------------------------------------------------------------------------------|
| 56A863A9-875E-4185-98A7-B882C64B5CE5 | Block abuse of exploited vulnerable signed drivers                                                  |
| 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C | Block Adobe Reader from creating child processes                                                    |
| D4F940AB-401B-4EFC-AADC-AD5F3C50688A | Block all Office applications from creating child processes                                         |
| 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 | Block credential stealing from the Windows local security authority subsystem (lsass.exe)           |
| BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 | Block executable content from email client and webmail                                              |
| 01443614-CD74-433A-B99E-2ECDC07BFC25 | Block executable files from running unless they meet a prevalence - age - or trusted list criterion |
| 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC | Block execution of potentially obfuscated scripts                                                   |
| D3E037E1-3EB8-44C8-A917-57927947596D | Block JavaScript or VBScript from launching downloaded executable content                           |
| 3B576869-A4EC-4529-8536-B80A7769E899 | Block Office applications from creating executable content                                          |
| 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 | Block Office applications from injecting code into other processes                                  |
| 26190899-1602-49E8-8B27-EB1D0A1CE869 | Block Office communication application from creating child processes                                |
| E6DB77E5-3DF2-4CF1-B95A-636979351E5B | Block persistence through WMI event subscription                                                    |
| D1E49AAC-8F56-4280-B9BA-993A6D77406C | Block process creations originating from PSExec and WMI commands                                    |
| B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 | Block untrusted and unsigned processes that run from USB                                            |
| 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B | Block Win32 API calls from Office macros                                                            |
| C1DB55AB-C21A-4637-BB3F-A12568109D35 | Use advanced protection against ransomware                                                          |
| A8F5898E-1DC8-49A9-9878-85004B8A61E6 | Block Webshell creation for Servers                                                                 |

# Implement ASR Rules 
Consult online documentation on deploying ASR Rules in audit mode to your network through Group policy or SCCM/Intune. a lot of work is required to move some of the rules to block mode 
to add exclusion this blog post here helps 
https://blog.nathanmcnulty.com/defender-for-endpoint-implementing-asr-rules/
- To be added exclusion list 
# Get the list of the availalbe ASR rule actiontypes 
```
DeviceEvents
| where ActionType startswith 'Asr'
```

# References
- https://asrgen.streamlit.app/ASR_Atomic_Testing

