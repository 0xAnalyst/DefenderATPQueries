

# List all Available Windows API telemtry
```
DeviceEvents
| where ActionType contains "ApiCall"
| summarize count() by ActionType
| project ActionType
```
