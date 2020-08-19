"""
Convert raw "Mordor" large-dataset events to "winlogbeat" 7.8 ECS format events
"Mordor" large dataset - https://mordordatasets.com/introduction.html
"""
from datetime import datetime
from dotty_dict import dotty
from mappings import sysmon_fields_mapping, windows_fields_mapping, common_registry_hives, sysmon_event_action, \
    sysmon_event_category, sysmon_event_type, powershell_fields_mapping
import re

powershell_winlogbeat_events = {400,
                                403,
                                600,
                                800,
                                4103,
                                4104,
                                4105,
                                4106}


def raw_event_to_winlogbeat_event(event_json):
    logbeat_event = {'@metadata': {
        "beat": "winlogbeat",
        "type": "doc",
        "version": "7.8.0",
        "topic": "winlogbeat"
    }}

    # meta

    # timestamp
    if '@timestamp' in event_json:
        logbeat_event['@timestamp'] = event_json['@timestamp']

    # host
    logbeat_event["host"] = {}
    if "host" in event_json:  # wec.internal.cloudapp.net
        logbeat_event["host"]["name"] = event_json["host"]

    if 'Hostname' in event_json:  # UTICA.dmevals.local
        logbeat_event['computer_name'] = event_json['Hostname']
        logbeat_event['host']['hostname'] = event_json['Hostname']
        del event_json['Hostname']

    # event
    logbeat_event['event'] = {}
    if 'EventID' in event_json:
        logbeat_event['event']["id"] = event_json['EventID']
        logbeat_event['event']["code"] = event_json['EventID']
        del event_json['EventID']

    if 'EventTime' in event_json:
        if 'Z' not in event_json['EventTime']:
            created = datetime.strptime(event_json['EventTime'], '%Y-%m-%d %H:%M:%S').isoformat()[:-3] + 'Z'
        else:
            created = datetime.strptime(event_json['EventTime'], '%Y-%m-%dT%H:%M:%S.%fZ').isoformat()[:-3] + 'Z'
        logbeat_event['event']["created"] = created
    logbeat_event['event']['dataset'] = "mordor"

    if 'Channel' in event_json:
        if '/' in event_json['Channel']:
            provider = event_json['Channel'].split("/")[0]
        else:
            provider = event_json['Channel']
        logbeat_event['event']['provider'] = provider

    if 'EventType' in event_json:
        logbeat_event['event']['type'] = event_json['EventType'].lower()

    # user:
    user_obj = {}
    if 'AccountType' in event_json:
        user_obj['type'] = event_json['AccountType']
        del event_json['AccountType']
    if 'AccountName' in event_json:
        user_obj['name'] = event_json['AccountName']
        del event_json['AccountName']
    if 'UserID' in event_json:
        user_obj['identifier'] = event_json['UserID']
        del event_json['UserID']
    if 'Domain' in event_json:
        user_obj['domain'] = event_json['Domain']
        del event_json['Domain']
    if user_obj:
        logbeat_event['user'] = user_obj

    # event data:
    logbeat_event['event_data'] = event_json

    return logbeat_event


def map_sysmon_fields(evt):
    evt_fields_to_add = dotty()
    if 'event_data' in evt:
        evt_fields = list(evt['event_data'].keys())
        for field in evt_fields:
            if field in sysmon_fields_mapping:
                evt_fields_to_add[sysmon_fields_mapping[field]] = evt['event_data'][field]
                del evt['event_data'][field]

    # event fields by event id
    event_id = evt['event']['id']
    if event_id in sysmon_event_action:
        evt_fields_to_add['event.action'] = sysmon_event_action[event_id]
    if event_id in sysmon_event_type:
        evt_fields_to_add['event.type'] = sysmon_event_type[event_id]
    if event_id in sysmon_event_category:
        evt_fields_to_add['event.category'] = sysmon_event_category[event_id]
    evt_fields_to_add['event.kind'] = 'event'
    evt_fields_to_add['event.module'] = 'sysmon'

    evt_fields_to_add = dict(evt_fields_to_add)
    # merge sub-dicts - event
    evt['event'] = {**evt['event'], **evt_fields_to_add['event']}
    del evt_fields_to_add['event']

    return {**evt, **evt_fields_to_add}


def map_windows_fields(evt):
    evt_fields_to_add = dotty()
    if 'event_data' in evt:
        evt_fields = list(evt['event_data'].keys())
        for field in evt_fields:
            if field in windows_fields_mapping:
                evt_fields_to_add[windows_fields_mapping[field]] = evt['event_data'][field]
                del evt['event_data'][field]

    evt_fields_to_add = dict(evt_fields_to_add)
    # merge sub-dicts - user
    if 'user' in evt and 'user' in evt_fields_to_add:
        evt['user'] = {**evt['user'], **evt_fields_to_add['user']}
        del evt_fields_to_add['user']

    return {**evt, **evt_fields_to_add}


def parse_timestamp(evt):
    if '@timestamp' in evt:
        if 'Z' not in evt['@timestamp']:
            evt['@timestamp'] = datetime.strptime(evt['@timestamp'], '%Y-%m-%d %H:%M:%S.%f').isoformat()[:-3] + 'Z'
        else:
            evt['@timestamp'] = datetime.strptime(evt['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ').isoformat()[:-3] + 'Z'
    return evt


def set_process_name_from_path(evt, path_field, name_field):
    d = dotty(evt)
    if name_field in d and d[name_field]:
        return
    if path_field in d:
        exe = d[path_field]
        d[name_field] = exe.split("\\")[-1]
    return {**evt, **dict(d)}


def split_command_line(evt, source, target):
    d = dotty(evt)
    if source in d and d[source]:
        d[target] = d[source].split(' ')[1:]
    return dict(d)


def add_user(evt, user_field="User"):
    d = dotty(evt)
    if "event_data." + user_field in d:
        user_parts = d["event_data." + user_field].split("\\")
        if len(user_parts) == 2:
            d["user.domain"] = user_parts[0]
            d["user.name"] = user_parts[1]
            del d["event_data." + user_field]
    return dict(d)


def set_additional_file_fields_from_path(evt):
    d = dotty(evt)
    if "file.path" in d and d["file.path"]:
        filepath = d["file.path"]
        d["file.name"] = filepath.split("\\")[-1]
        d["file.directory"] = '\\'.join(filepath.split("\\")[:-1])
    return {**evt, **dict(d)}


def _get_hash_path(namespace, hash_key):
    if hash_key == 'imphash':
        return namespace + ".pe.imphash"
    return namespace + ".hash." + hash_key


def add_hashes(evt, namespace, hash_field):
    d = dotty(evt)
    if hash_field in d:
        hashes = d[hash_field]
        for _hash in hashes.split(","):
            parts = _hash.split("=")
            if len(parts) != 2:
                continue
            key = parts[0].lower()
            value = parts[1].lower()
            path = _get_hash_path(namespace, key)
            d[path] = value
            d['hash.' + key] = value
    return {**evt, **dict(d)}


def split_file_hashes(evt):
    return add_hashes(evt, "file", "event_data.Hashes")


def split_file_hash(evt):
    return add_hashes(evt, "file", "event_data.Hash")


def split_process_hash(evt):
    return add_hashes(evt, "process", "event_data.Hashes")


def add_network_direction(evt):
    d = dotty(evt)
    if "event_data.Initiated" in d:
        if d["event_data.Initiated"] == "true":
            d["network.direction"] = "outbound"
        elif d["event_data.Initiated"] == "false":
            d["network.direction"] = "inbound"
        evt = {**evt, **dict(d)}
        del evt["event_data"]["Initiated"]
    return evt


def add_network_type(evt):
    d = dotty(evt)
    if "event_data.SourceIsIpv6" in d:
        if d["event_data.SourceIsIpv6"] == "true":
            d["network.type"] = "ipv6"
        elif d["event_data.SourceIsIpv6"] == "false":
            d["network.type"] = "ipv4"
        evt = {**evt, **dict(d)}
        del evt["event_data"]["SourceIsIpv6"]
        if "event_data.DestinationIsIpv6" in d:
            del evt["event_data"]["DestinationIsIpv6"]
    return evt


def set_additional_signature_fields(evt):
    d = dotty(evt)
    if "event_data.Signed" in d and d["event_data.Signed"]:
        d["file.code_signature.signed"] = True
    if "event_data.SignatureStatus" in d:
        if d["event_data.SignatureStatus"] == "Valid":
            d["file.code_signature.valid"] = True
        else:
            d["file.code_signature.valid"] = False
    return {**evt, **dict(d)}


def set_registry_fields(evt):
    d = dotty(evt)
    if "event_data.TargetObject" in d and d["event_data.TargetObject"]:
        path = d["event_data.TargetObject"]
        d["registry.path"] = path
        path_tokens = path.split("\\")
        hive = None
        if path_tokens[0] in common_registry_hives:
            hive = common_registry_hives[path_tokens[0]]
            d["registry.hive"] = hive
            if len(path_tokens[1:]) > 0:
                d["registry.key"] = "\\".join(path_tokens[1:])
        value = path_tokens[-1]
        d["registry.value"] = value
    return {**evt, **dict(d)}


# PowerShell events func -
# based on https://github.com/elastic/beats/blob/3ef18111c43dad3de7aebe944935ee2e36cab3d6/x-pack/winlogbeat/module/powershell/config/winlogbeat-powershell.js
def dissect_4xx_and_600_and_800(event_data, is_800=False):
    d = {}
    if 'Message' not in event_data:
        return d
    message = event_data['Message']
    message_chunks = message.split("\r\n\r\n")
    if is_800 and len(message_chunks) > 1:
        message_parts = message[1].split("\r\n\t")
    else:
        message_parts = message.split("\r\n\t")
    for kv in message_parts:
        if "=" in kv:
            kv = kv.replace('\r','').replace('\n','').replace('\t','')
            kv_parts = kv.split("=")
            if len(kv_parts) == 2:
                key = kv_parts[0].strip()
                value = kv_parts[1].strip()
                if value != "":
                    d[key] = value
    return d


def dissect_4103(event_data):
    d = {}
    if 'Message' not in event_data:
        return d
    message = event_data['Message']
    message_parts = message.split("        ")
    for kv in message_parts:
        if " = " in kv:
            kv_parts = kv.split(" = ")
            if len(kv_parts) == 2:
                key = "".join(kv_parts[0].strip().split(" "))
                value = kv_parts[1].strip().split("\r\n\r\n\r\n")[0]
                if value != "":
                    d[key] = value
    return d


def map_powershell_fields(evt):
    d = dotty(evt)
    if 'event_data' in evt:
        evt_fields = list(evt['event_data'].keys())
        for field in evt_fields:
            if field in powershell_fields_mapping:
                d[powershell_fields_mapping[field]] = evt['event_data'][field]
                del d['event_data'][field]
    return dict(d)


def add_engine_version(evt):
    d = dotty(evt)
    if "event_data.EngineVersion" in d:
        engine_version = d["event_data.EngineVersion"]
        if engine_version:
            d["powershell.engine.version"] = engine_version
            del d["event_data.EngineVersion"]
    return dict(d)


def add_pipeline_id(evt):
    d = dotty(evt)
    if "event_data.PipelineId" in d:
        id = d["event_data.PipelineId"]
        if id:
            d["powershell.pipeline_id"] = id
            del d["event_data.PipelineId"]
    return dict(d)


def add_runspace_id(evt):
    d = dotty(evt)
    if "event_data.RunspaceId" in d:
        id = d["event_data.RunspaceId"]
        if id:
            d["powershell.runspace_id"] = id
            del d["event_data.RunspaceId"]
    return dict(d)


def add_process_args(evt):
    evt = split_command_line(evt, "process.command_line", "process.args")
    d = dotty(evt)
    if "process.args" in d and d["process.args"] and len(d["process.args"]) > 0:
        d["process.args_count"] = len(d["process.args"])
    return dict(d)


def add_executable_version(evt):
    d = dotty(evt)
    if "event_data.HostVersion" in d:
        version = d["event_data.HostVersion"]
        if version:
            d["powershell.process.executable_version"] = version
            del d["event_data.HostVersion"]
    return dict(d)


def add_file_info(evt):
    d = dotty(evt)
    if "event_data.ScriptName" in d:
        script_name = d["event_data.ScriptName"]
        if script_name:
            d["file.path"] = script_name
            d["file.name"] = script_name.split("\\")[-1]
            d["file.directory"] = '\\'.join(script_name.split("\\")[:-1])
            if '.' in script_name:
                script_extension = script_name.split(".")[-1]
                if script_extension:
                    d["file.extension"] = script_extension
            del d["event_data.ScriptName"]
    return dict(d)


def add_command_value(evt):
    d = dotty(evt)
    if "event_data.CommandLine" in d:
        cmd_value = d["event_data.CommandLine"]
        if cmd_value:
            d["powershell.command.value"] = cmd_value
            del d["event_data.CommandLine"]
    return dict(d)


def add_command_path(evt):
    d = dotty(evt)
    if "event_data.CommandPath" in d:
        cmd_path = d["event_data.CommandPath"]
        if cmd_path:
            d["powershell.command.path"] = cmd_path
            del d["event_data.CommandPath"]
    return dict(d)


def add_command_name(evt):
    d = dotty(evt)
    if "event_data.CommandName" in d:
        cmd_name = d["event_data.CommandName"]
        if cmd_name:
            d["powershell.command.name"] = cmd_name
            del d["event_data.CommandName"]
    return dict(d)


def add_command_type(evt):
    d = dotty(evt)
    if "event_data.CommandType" in d:
        cmd_type = d["event_data.CommandType"]
        if cmd_type:
            d["powershell.command.type"] = cmd_type
            del d["event_data.CommandType"]
    return dict(d)


def _parse_raw_detail(raw):
    raw_pattern = r'^(.+)\((.+)\)\:\s*(.+)?$'
    parameter_binding_pattern = r'^.*name\=(.+);\s*value\=(.+)$'
    match_obj = re.match(raw_pattern, raw)

    if not match_obj or len(match_obj.groups()) != 3:
        return {"value": raw}

    g_type = match_obj.group(1).strip()
    g_related_command = match_obj.group(2).strip()
    g_value = match_obj.group(3).strip()

    if g_type != "ParameterBinding":
        return {"type": g_type, "related_command": g_related_command, "value": g_value}

    match_parameter_binding_obj = re.match(parameter_binding_pattern, g_value)
    if not match_parameter_binding_obj or len(match_parameter_binding_obj.groups()) != 2:
        return {"value": g_value}

    return {"type": g_type, "related_command": g_related_command, "name": match_parameter_binding_obj.group(1).strip() ,"value": match_parameter_binding_obj.group(2).strip()}


def add_command_invocation_details(evt):
    d = dotty(evt)
    if 'event_data.Message' not in d:
        return evt
    message = d['event_data.Message']
    if 'Details:' in message:
        message = message.split("Details:")[1:]
        if len(message) > 0:
            message = message[0]
            details = []
            for raw in message.split("\n"):
                if raw.strip() == '':
                    continue
                details.append(_parse_raw_detail(raw))
            if len(details) > 0:
                d["powershell.command.invocation_details"] = details
    return dict(d)


def add_connected_user(evt):
    d = dotty(evt)
    if "event_data.ConnectedUser" in d:
        user_parts = d["event_data.ConnectedUser"].split("\\")
        if len(user_parts) == 2:
            d["powershell.connected_user.domain"] = user_parts[0]
            d["powershell.connected_user.name"] = user_parts[1]
        del d["event_data.ConnectedUser"]
    return dict(d)


def add_script_block_id(evt):
    d = dotty(evt)
    if "event_data.ScriptBlockId" in d:
        id = d["event_data.ScriptBlockId"]
        if id:
            d["powershell.file.script_block_id"] = id
            del d["event_data.ScriptBlockId"]
    return dict(d)


def add_script_block_text(evt):
    d = dotty(evt)
    if "event_data.ScriptBlockText" in d:
        text = d["event_data.ScriptBlockText"]
        if text:
            d["powershell.file.script_block_text"] = text
            del d["event_data.ScriptBlockText"]
    return dict(d)


def event_4xx_and_600_and_800_common(evt, is_800=False):
    if 'event_data' in evt:
        message = dissect_4xx_and_600_and_800(evt['event_data'], is_800)
        evt['event_data'] = {**evt['event_data'], **message}
    evt = map_powershell_fields(evt)
    evt = add_engine_version(evt)
    evt = add_pipeline_id(evt)
    evt = add_runspace_id(evt)
    evt = add_process_args(evt)
    evt = add_executable_version(evt)
    evt = add_file_info(evt)
    evt = add_command_value(evt)
    evt = add_command_path(evt)
    evt = add_command_name(evt)
    evt = add_command_type(evt)
    return evt


def event_4105_and_4106_common(evt):
    evt = add_runspace_id(evt)
    evt = add_script_block_id(evt)
    return evt


def event400(evt):
    if 'event' in evt:
        evt['event']['category'] = 'process'
        evt['event']['type'] = 'start'
    evt = event_4xx_and_600_and_800_common(evt)
    return evt


def event403(evt):
    if 'event' in evt:
        evt['event']['category'] = 'process'
        evt['event']['type'] = 'end'
    evt = event_4xx_and_600_and_800_common(evt)
    return evt


def event600(evt):
    if 'event' in evt:
        evt['event']['category'] = 'process'
        evt['event']['type'] = 'info'
    evt = event_4xx_and_600_and_800_common(evt)
    return evt


def event800(evt):
    if 'event' in evt:
        evt['event']['category'] = 'process'
        evt['event']['type'] = 'info'
    evt = event_4xx_and_600_and_800_common(evt, is_800=True)
    evt = add_user(evt, user_field="UserId")
    evt = add_command_invocation_details(evt)
    return evt


def event4103(evt):
    if 'event_data' in evt:
        message = dissect_4103(evt['event_data'])
        evt['event_data'] = {**evt['event_data'], **message}
    if 'event' in evt:
        evt['event']['category'] = 'process'
        evt['event']['type'] = 'info'
    evt = map_powershell_fields(evt)
    evt = add_engine_version(evt)
    evt = add_pipeline_id(evt)
    evt = add_runspace_id(evt)
    evt = add_process_args(evt)
    evt = add_executable_version(evt)
    evt = add_file_info(evt)
    evt = add_command_value(evt)
    evt = add_command_path(evt)
    evt = add_command_name(evt)
    evt = add_command_type(evt)
    evt = add_user(evt)
    evt = add_connected_user(evt)
    evt = add_command_invocation_details(evt)
    return evt


def event4104(evt):
    if 'event' in evt:
        evt['event']['category'] = 'process'
        evt['event']['type'] = 'info'
    evt = add_file_info(evt)
    evt = add_script_block_id(evt)
    evt = add_script_block_text(evt)
    return evt


def event4105(evt):
    if 'event' in evt:
        evt['event']['category'] = 'process'
        evt['event']['type'] = 'start'
    evt = event_4105_and_4106_common(evt)
    return evt


def event4106(evt):
    if 'event' in evt:
        evt['event']['category'] = 'process'
        evt['event']['type'] = 'end'
    evt = event_4105_and_4106_common(evt)
    return evt


def convert_event(evt):
    if 'event' in evt and 'id' in evt['event']:
        event_id = evt['event']['id']
        if (1 <= event_id <= 23) or event_id == 255:
            evt = map_sysmon_fields(evt)
            evt = set_process_name_from_path(evt, "process.executable", "process.name")
            evt = split_command_line(evt, "process.command_line", "process.args")
            evt = set_process_name_from_path(evt, "process.parent.executable", "process.parent.name")
            evt = split_command_line(evt, "process.parent.command_line", "process.parent.args")
            evt = add_user(evt)
            evt = set_additional_file_fields_from_path(evt)
            evt = split_file_hashes(evt)
            evt = split_file_hash(evt)
            evt = split_process_hash(evt)
            evt = add_network_direction(evt)
            evt = add_network_type(evt)
            evt = set_additional_signature_fields(evt)
            evt = set_registry_fields(evt)
        elif event_id in powershell_winlogbeat_events:  # PowerShell events
            """
                {400,
                403,
                600,
                800,
                4103,
                4104,
                4105,
                4106}
            """
            if event_id == 400:
                evt = event400(evt)
            elif event_id == 403:
                evt = event403(evt)
            elif event_id == 600:
                evt = event600(evt)
            elif event_id == 800:
                evt = event800(evt)
            elif event_id == 4103:
                evt = event4103(evt)
            elif event_id == 4104:
                evt = event4104(evt)
            elif event_id == 4105:
                evt = event4105(evt)
            elif event_id == 4106:
                evt = event4106(evt)
        else:
            evt = map_windows_fields(evt)
            evt = set_process_name_from_path(evt, "process.executable", "process.name")
            evt = set_process_name_from_path(evt, "process.parent.executable", "process.parent.name")
    evt = parse_timestamp(evt)
    return evt
