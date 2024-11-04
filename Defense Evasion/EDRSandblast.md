# Rule Documentation: Detection of Suspicious Driver Loads Indicative of EDR Bypass

## Description
This detection rule identifies the loading of suspicious drivers, such as `WN_64.sys` and `wnbios.sys`, which are commonly associated with techniques used to bypass Endpoint Detection and Response (EDR) systems. Attackers may use malicious or modified drivers to disable security software, avoid detection, and establish a foothold within the system. The identified drivers have been linked to sophisticated extortion and ransomware campaigns, as described by Palo Alto Networks' Unit 42 in their analysis of EDR bypass techniques.

Monitoring driver load events for these specific filenames can help detect early signs of an attempted security bypass and give security teams the opportunity to investigate and mitigate the threat before further damage occurs.

- [Palo Alto Networks Unit 42: EDR Bypass Extortion Attempt](https://unit42.paloaltonetworks.com/edr-bypass-extortion-attempt-thwarted/?pdf=download&lg=en&_wpnonce=70be2dde45)

## Detection Logic
- Monitors `DeviceEvents` where:
  - The `ActionType` is `"DriverLoad"`.
  - The `FileName` includes `"WN_64.sys"` or `"wnbios.sys"`.

## Tags
- EDR Bypass
- Driver Load
- Security Evasion
- Ransomware
- Suspicious Activity

## Search Query
```kql
DeviceEvents
| where ActionType == "DriverLoad"
| where FileName has_any("WN_64.sys", "wnbios.sys")
```

You can ass add the following line to detect the specific vulnerable drivers 
```| extend parsed = parse_json(AdditionalFields)
   |  where FileName has_any("WN_64.sys", "wnbios.sys") parsed.ImageSHA256 has_any("6106d1ce671b92d522144fcd3bc01276a975fe5d5b0fde09ca1cca16d09b7143","6106d1ce671b92d522144fcd3bc01276a975fe5d5b0fde09ca1cca16d09b7143")
```
