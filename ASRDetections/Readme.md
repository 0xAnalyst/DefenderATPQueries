# What does ASR rules offers
ASR rules offer a broad range of built-in rules to secure your endpoint, covering areas like Office applications (think macros, DDE’s, etc.) subversion or leverage, but also things like Webmail, script, WMI, LSASS, and much more.
## To implement ASR rules following is Required:
  - Computers running Windows 10, versions 1709 and later,  Windows Server version 1803 (Semi-Annual Channel or later) and Windows Server 2019
  - Windows 10 Pro/Enterprise/Education
  - Microsoft Defender antivirus must be active (cannot be in passive mode!)
  - Some rules require cloud-delivered protection to be enabled
References https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/demystifying-attack-surface-reduction-rules-part-1/ba-p/1306420



# ASR rule name to ASR guid
- Block abuse of exploited vulnerable signed drivers	56a863a9-875e-4185-98a7-b882c64b5ce5
- Block Adobe Reader from creating child processes	7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c
- Block all Office applications from creating child processes	d4f940ab-401b-4efc-aadc-ad5f3c50688a
- Block credential stealing from the Windows local security authority subsystem (lsass.exe)	9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
- Block executable content from email client and webmail	be9ba2d9-53ea-4cdc-84e5-9b1eeee46550
- Block executable files from running unless they meet a prevalence, age, or trusted list criterion	01443614-cd74-433a-b99e-2ecdc07bfc25
- Block execution of potentially obfuscated scripts	5beb7efe-fd9a-4556-801d-275e5ffc04cc
- Block JavaScript or VBScript from launching downloaded executable content	d3e037e1-3eb8-44c8-a917-57927947596d
- Block Office applications from creating executable content	3b576869-a4ec-4529-8536-b80a7769e899
- Block Office applications from injecting code into other processes	75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84
- Block Office communication application from creating child processes	26190899-1602-49e8-8b27-eb1d0a1ce869
- Block persistence through WMI event subscription
* File and folder exclusions not supported.	e6db77e5-3df2-4cf1-b95a-636979351e5b
- Block process creations originating from PSExec and WMI commands	d1e49aac-8f56-4280-b9ba-993a6d77406c
- Block rebooting machine in Safe Mode (preview)	33ddedf1-c6e0-47cb-833e-de6133960387
- Block untrusted and unsigned processes that run from USB	b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4
- Block use of copied or impersonated system tools (preview)	c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb
- Block Webshell creation for Servers	a8f5898e-1dc8-49a9-9878-85004b8a61e6
- Block Win32 API calls from Office macros	92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b
- Use advanced protection against ransomware	c1db55ab-c21a-4637-bb3f-a12568109d35

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

