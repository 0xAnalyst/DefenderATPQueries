# What Does ASR rules offers
ASR rules offer a broad range of built-in rules to secure your endpoint, covering areas like Office applications (think macros, DDE’s, etc.) subversion or leverage, but also things like Webmail, script, WMI, LSASS, and much more.
References https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/demystifying-attack-surface-reduction-rules-part-1/ba-p/1306420
# Get the list of the availalbe ASR rules 
```
DeviceEvents
| where ActionType startswith 'Asr'
```
