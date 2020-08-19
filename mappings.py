windows_fields_mapping = {
    "AccountName": "user.name",
    "AccountDomain": "user.domain",
    "ClientAddress": "source.ip",
    "ClientName": "source.domain",
    "LogonID": "logon.id",
    "TargetUserSid": "user.id",
    "TargetUserName": "user.name",
    "TargetDomainName": "user.domain",
    "IpAddress": "source.ip",
    "IpPort": "source.port",
    "WorkstationName": "source.domain",
    "NewProcessId": "process.pid",
    "NewProcessName": "process.executable",
    "ProcessName": "process.executable",
    "ParentProcessName": "process.parent.executable"
}


sysmon_fields_mapping = {
    "UtcTime": "@timestamp",
    "ProcessGuid": "process.entity_id",
    "ProcessId": "process.pid",
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "CurrentDirectory": "process.working_directory",
    "ParentProcessGuid": "process.parent.entity_id",
    "ParentProcessId": "process.parent.pid",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "TargetFilename": "file.path",
    "Protocol": "network.transport",
    "SourceIp": "source.ip",
    "SourceHostname": "source.domain",
    "SourcePort": "source.port",
    "DestinationIp": "destination.ip",
    "DestinationHostname": "destination.domain",
    "DestinationPort": "destination.port",
    "DestinationPortName": "network.protocol",
    "ImageLoaded": "file.path",
    "Signature": "file.code_signature.subject_name",
    "SignatureStatus": "file.code_signature.status",
    "SourceProcessGuid": "process.entity_id",
    "SourceProcessId": "process.pid",
    "SourceImage": "process.executable",
    "Device": "file.path",
    "SourceThreadId": "process.thread.id",
    "PipeName": "file.name",
    "Destination": "process.executable",
    "QueryName": "dns.question.name",
    "QueryStatus": "sysmon.dns.status",
    "RuleName": "rule.name",
    "Archived": "sysmon.file.archived",
    "IsExecutable": "sysmon.file.is_executable",
    "ID": "error.code"
}

common_registry_hives = {
    "HKEY_CLASSES_ROOT": "HKCR",
    "HKCR": "HKCR",
    "HKEY_CURRENT_CONFIG": "HKCC",
    "HKCC": "HKCC",
    "HKEY_CURRENT_USER": "HKCU",
    "HKCU": "HKCU",
    "HKEY_DYN_DATA": "HKDD",
    "HKDD": "HKDD",
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKLM": "HKLM",
    "HKEY_PERFORMANCE_DATA": "HKPD",
    "HKPD": "HKPD",
    "HKEY_USERS": "HKU",
    "HKU": "HKU"
}

sysmon_event_action = {
    1: "Process Create (rule: ProcessCreate)",
    2: "File creation time changed (rule: FileCreateTime)",
    3: "Network connection detected (rule: NetworkConnect)",
    4: "Sysmon service state changed",
    5: "Process terminated (rule: ProcessTerminate)",
    6: "Driver loaded (rule: DriverLoad)",
    7: "Image loaded (rule: ImageLoad)",
    8: "CreateRemoteThread detected (rule: CreateRemoteThread)",
    9: "RawAccessRead detected (rule: RawAccessRead)",
    10: "Process Access (rule: ProcessAccess)",
    11: "File created (rule: FileCreate)",
    12: "Registry object added or deleted (rule: RegistryEvent)",
    13: "Registry value set (rule: RegistryEvent)",
    14: "Registry object renamed (rule: RegistryEvent)",
    15: "File stream created (rule: FileCreateStreamHash)",
    16: "Sysmon config state changed",
    17: "Pipe Created (rule: PipeEvent)",
    18: "Pipe Connected (rule: PipeEvent)",
    19: "WmiEventFilter activity detected (rule: WmiEvent)",
    20: "WmiEventConsumer activity detected (rule: WmiEvent)",
    21: "WmiEventConsumerToFilter activity detected (rule: WmiEvent)"
}

sysmon_event_category = {
    1: "process",
    5: "process"
}

sysmon_event_type = {
    1: "process_start",
    5: "process_end"
}

powershell_fields_mapping = {
    "SequenceNumber": "event.sequence",
    "NewEngineState": "powershell.engine.new_state",
    "PreviousEngineState": "powershell.engine.previous_state",
    "NewProviderState": "powershell.provider.new_state",
    "ProviderName": "powershell.provider.name",
    "HostId": "process.entity_id",
    "HostApplication": "process.command_line",
    "HostName": "process.title",
    "DetailTotal": "powershell.total",
    "DetailSequence": "powershell.sequence",
    "ShellID": "powershell.id",
    "MessageNumber": "powershell.sequence",
    "MessageTotal": "powershell.total",
}