


```
DeviceEvents
| where ActionType contains "ApiCall"
| summarize count() by ActionType
| project ActionType```
