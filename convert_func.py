"""
Convert raw "Mordor" large-dataset events to "winlogbeat" 7.8 ECS format events
"Mordor" large dataset - https://mordordatasets.com/introduction.html
"""
from datetime import datetime
from dotty_dict import dotty
from mappings import sysmon_fields_mapping, windows_fields_mapping, common_registry_hives, sysmon_event_action, \
    sysmon_event_category, sysmon_event_type


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
    if 'user' in evt:
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
    return {**evt, **dict(d)}


def add_user(evt):
    d = dotty(evt)
    if "event_data.User" in d:
        user_parts = d["event_data.User"].split("\\")
        if len(user_parts) == 2:
            d["user.domain"] = user_parts[0]
            d["user.name"] = user_parts[1]
            evt = {**evt, **dict(d)}
            del evt["event_data"]["User"]
    return evt


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
        else:
            evt = map_windows_fields(evt)
            evt = set_process_name_from_path(evt, "process.executable", "process.name")
            evt = set_process_name_from_path(evt, "process.parent.executable", "process.parent.name")
    evt = parse_timestamp(evt)
    return evt
