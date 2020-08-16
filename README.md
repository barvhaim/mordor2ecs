# mordor2ecs
Raw Mordor's Windows Log to ECS format

Input: mordor large dataset after extraction, for example,
`mordor-master/datasets/large/apt29/day1/apt29_evals_day1_manual_2020-05-01225525.json`

Output: converted events to winlogbeat 7.8 ECS format
```
{"@metadata": {"beat": "winlogbeat", "type": "doc", "version": "7.8.0", "topic": "winlogbeat"}, "@timestamp": "2020-05-02T02:55:23.551Z", "host": {"name": "wec.internal.cloudapp.net", "hostname": "UTICA.dmevals.local"}, "computer_name": "UTICA.dmevals.local", "event": {"id": 10, "code": 10, "created": "2020-05-01T22:55Z", "dataset": "mordor", "provider": "Microsoft-Windows-Sysmon/Operational", "type": "info"}, "user": {"type": "User", "name": "SYSTEM", "identifier": "S-1-5-18", "domain": "NT AUTHORITY"}, "event_data": {"EventTime": "2020-05-01 22:55:23", "port": 60737, "Message": "Process accessed:\r\nRuleName: -\r\nUtcTime: 2020-05-02 02:55:23.551\r\nSourceProcessGUID: {6bbf237a-cafb-5eac-1000-000000000400}\r\nSourceProcessId: 900\r\nSourceThreadId: 504\r\nSourceImage: C:\\windows\\system32\\svchost.exe\r\nTargetProcessGUID: {6bbf237a-cb97-5eac-6202-000000000400}\r\nTargetProcessId: 2092\r\nTargetImage: C:\\windows\\System32\\svchost.exe\r\nGrantedAccess: 0x1000\r\nCallTrace: C:\\windows\\SYSTEM32\\ntdll.dll+9c584|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+222a3|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+1a172|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+19e3b|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+19318|C:\\windows\\SYSTEM32\\ntdll.dll+3089d|C:\\windows\\SYSTEM32\\ntdll.dll+34634|C:\\windows\\System32\\KERNEL32.DLL+17bd4|C:\\windows\\SYSTEM32\\ntdll.dll+6ced1", "TargetProcessId": "2092", "SourceModuleName": "eventlog", "tags": ["mordorDataset"], "@version": "1", "SourceName": "Microsoft-Windows-Sysmon", "TargetImage": "C:\\windows\\System32\\svchost.exe", "host": "wec.internal.cloudapp.net", "Task": 10, "ThreadID": 4396, "EventReceivedTime": "2020-05-01 22:55:26", "CallTrace": "C:\\windows\\SYSTEM32\\ntdll.dll+9c584|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+222a3|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+1a172|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+19e3b|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+19318|C:\\windows\\SYSTEM32\\ntdll.dll+3089d|C:\\windows\\SYSTEM32\\ntdll.dll+34634|C:\\windows\\System32\\KERNEL32.DLL+17bd4|C:\\windows\\SYSTEM32\\ntdll.dll+6ced1", "Keywords": -9223372036854775808, "RecordNumber": 138294, "SourceModuleType": "im_msvistalog", "@timestamp": "2020-05-02T02:55:26.493Z", "SeverityValue": 2, "Version": 3, "OpcodeValue": 0, "Severity": "INFO", "Channel": "Microsoft-Windows-Sysmon/Operational", "GrantedAccess": "0x1000", "SourceProcessGUID": "{6bbf237a-cafb-5eac-1000-000000000400}", "EventType": "INFO", "TargetProcessGUID": "{6bbf237a-cb97-5eac-6202-000000000400}", "ExecutionProcessID": 3496, "ProviderGuid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"}, "process": {"thread": {"id": "504"}, "executable": "C:\\windows\\system32\\svchost.exe", "pid": "900", "name": "svchost.exe"}, "rule": {"name": "-"}}

{"@metadata": {"beat": "winlogbeat", "type": "doc", "version": "7.8.0", "topic": "winlogbeat"}, "@timestamp": "2020-05-02T02:55:37.785Z", "host": {"name": "wec.internal.cloudapp.net", "hostname": "UTICA.dmevals.local"}, "computer_name": "UTICA.dmevals.local", "event": {"id": 10, "code": 10, "created": "2020-05-01T22:55Z", "dataset": "mordor", "provider": "Microsoft-Windows-Sysmon/Operational", "type": "info"}, "user": {"type": "User", "name": "SYSTEM", "identifier": "S-1-5-18", "domain": "NT AUTHORITY"}, "event_data": {"EventTime": "2020-05-01 22:55:37", "port": 60737, "Message": "Process accessed:\r\nRuleName: -\r\nUtcTime: 2020-05-02 02:55:37.785\r\nSourceProcessGUID: {6bbf237a-cafb-5eac-1000-000000000400}\r\nSourceProcessId: 900\r\nSourceThreadId: 504\r\nSourceImage: C:\\windows\\system32\\svchost.exe\r\nTargetProcessGUID: {6bbf237a-cb97-5eac-6202-000000000400}\r\nTargetProcessId: 2092\r\nTargetImage: C:\\windows\\System32\\svchost.exe\r\nGrantedAccess: 0x1000\r\nCallTrace: C:\\windows\\SYSTEM32\\ntdll.dll+9c584|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+222a3|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+1a172|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+19e3b|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+19318|C:\\windows\\SYSTEM32\\ntdll.dll+3089d|C:\\windows\\SYSTEM32\\ntdll.dll+34634|C:\\windows\\System32\\KERNEL32.DLL+17bd4|C:\\windows\\SYSTEM32\\ntdll.dll+6ced1", "TargetProcessId": "2092", "SourceModuleName": "eventlog", "tags": ["mordorDataset"], "@version": "1", "SourceName": "Microsoft-Windows-Sysmon", "TargetImage": "C:\\windows\\System32\\svchost.exe", "host": "wec.internal.cloudapp.net", "Task": 10, "ThreadID": 4396, "EventReceivedTime": "2020-05-01 22:55:39", "CallTrace": "C:\\windows\\SYSTEM32\\ntdll.dll+9c584|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+222a3|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+1a172|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+19e3b|C:\\windows\\SYSTEM32\\psmserviceexthost.dll+19318|C:\\windows\\SYSTEM32\\ntdll.dll+3089d|C:\\windows\\SYSTEM32\\ntdll.dll+34634|C:\\windows\\System32\\KERNEL32.DLL+17bd4|C:\\windows\\SYSTEM32\\ntdll.dll+6ced1", "Keywords": -9223372036854775808, "RecordNumber": 138362, "SourceModuleType": "im_msvistalog", "@timestamp": "2020-05-02T02:55:39.614Z", "SeverityValue": 2, "Version": 3, "OpcodeValue": 0, "Severity": "INFO", "Channel": "Microsoft-Windows-Sysmon/Operational", "GrantedAccess": "0x1000", "SourceProcessGUID": "{6bbf237a-cafb-5eac-1000-000000000400}", "EventType": "INFO", "TargetProcessGUID": "{6bbf237a-cb97-5eac-6202-000000000400}", "ExecutionProcessID": 3496, "ProviderGuid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"}, "process": {"thread": {"id": "504"}, "executable": "C:\\windows\\system32\\svchost.exe", "pid": "900", "name": "svchost.exe"}, "rule": {"name": "-"}}
```

