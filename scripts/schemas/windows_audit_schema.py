"""Canonical Windows event log schema builders.

Two distinct event streams (different Channels, separate ingest into OCI
Log Analytics):

1. Security (Microsoft-Windows-Security-Auditing provider)
   Channel:  "Security"
   EventIDs: 4625, 4624, 4672, 4688, 4697, 4698, 4720, 4732, 4769, 4776,
             4662, 4663, 1102, 4946, 4657 ...

2. Sysmon (Microsoft-Windows-Sysmon/Operational provider)
   Channel:  "Microsoft-Windows-Sysmon/Operational"
   EventIDs: 1 (process), 3 (network), 8 (CreateRemoteThread), 10 (ProcessAccess),
             11 (FileCreate), 17 (PipeCreated), 22 (DnsQuery) ...

The two streams share some field names (EventID, TimeCreated, Computer,
Channel, Provider, User) but have different record-specific fields, and
they map to different OCI Log Analytics source types:
    'Windows Security Events'  vs  'Windows Sysmon Events'

OCI Log Analytics parsed display-name columns (added at ingest):
    'Event ID', 'Host Name (Server)', 'Subject User Name', 'Source IP',
    'Logon Type', 'Process Name', 'Command Line', 'Target User Name',
    'Image', 'Pipe Name', 'Query Name' (Sysmon-specific)
"""

from __future__ import annotations

from typing import Any


def build_windows_security_event(
    event_id: int,
    *,
    event_time: str,
    computer: str,
    user: str,
    process_id: int = 0,
    target_user_name: str = "",
    subject_user_name: str = "",
    subject_domain_name: str = "",
    source_address: str = "",
    logon_type: int | str = "",
    process_name: str = "",
    new_process_name: str = "",
    command_line: str = "",
    object_name: str = "",
    access_mask: str = "",
    failure_reason: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a Windows Security Auditing event (Channel: Security)."""
    event: dict[str, Any] = {
        "log_source_identifier": "Windows Security Events",
        "EventID": event_id,
        "TimeCreated": event_time,
        "Computer": computer,
        "Channel": "Security",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "User": user,
        "ProcessId": process_id,
    }

    # Source-native camelCase/PascalCase fields (what Windows emits)
    native_fields = {
        "TargetUserName": target_user_name,
        "SubjectUserName": subject_user_name or user,
        "SubjectDomainName": subject_domain_name,
        "SourceAddress": source_address,
        "LogonType": logon_type,
        "ProcessName": process_name,
        "NewProcessName": new_process_name,
        "CommandLine": command_line,
        "ObjectName": object_name,
        "AccessMask": access_mask,
        "FailureReason": failure_reason,
    }
    for k, v in native_fields.items():
        if v not in ("", 0, None):
            event[k] = v

    # OCI Log Analytics display-name parallel columns
    event["Log Source"] = "Windows Security Events"
    event["Event ID"] = event_id
    event["Host Name (Server)"] = computer
    event["Host Name"] = computer
    event["User Name"] = user
    event["Subject User Name"] = subject_user_name or user
    if target_user_name:
        event["Target User Name"] = target_user_name
    if source_address:
        event["Source IP"] = source_address
        event["Source Address"] = source_address
    if logon_type not in ("", None):
        event["Logon Type"] = str(logon_type)
    if new_process_name:
        event["New Process Name"] = new_process_name
        event["Process Name"] = new_process_name
    elif process_name:
        event["Process Name"] = process_name
    if command_line:
        event["Command Line"] = command_line
    if object_name:
        event["Object Name"] = object_name
    if failure_reason:
        event["Failure Reason"] = failure_reason

    if extra:
        event.update(extra)
    return event


def build_windows_sysmon_event(
    event_id: int,
    *,
    event_time: str,
    computer: str,
    user: str,
    image: str = "",
    command_line: str = "",
    parent_image: str = "",
    parent_command_line: str = "",
    target_image: str = "",
    source_image: str = "",
    pipe_name: str = "",
    query_name: str = "",
    query_results: str = "",
    target_filename: str = "",
    hashes: str = "",
    destination_ip: str = "",
    destination_port: int | str = "",
    granted_access: str = "",
    call_trace: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a Sysmon event (Channel: Microsoft-Windows-Sysmon/Operational)."""
    event: dict[str, Any] = {
        "log_source_identifier": "Windows Sysmon Events",
        "EventID": event_id,
        "TimeCreated": event_time,
        "UtcTime": event_time,
        "Computer": computer,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider": "Microsoft-Windows-Sysmon",
        "User": user,
    }

    native_fields = {
        "Image": image,
        "CommandLine": command_line,
        "ParentImage": parent_image,
        "ParentCommandLine": parent_command_line,
        "TargetImage": target_image,
        "SourceImage": source_image,
        "PipeName": pipe_name,
        "QueryName": query_name,
        "QueryResults": query_results,
        "TargetFilename": target_filename,
        "Hashes": hashes,
        "DestinationIp": destination_ip,
        "DestinationPort": destination_port,
        "GrantedAccess": granted_access,
        "CallTrace": call_trace,
    }
    for k, v in native_fields.items():
        if v not in ("", 0, None):
            event[k] = v

    # OCI Log Analytics display-name parallel columns
    event["Log Source"] = "Windows Sysmon Events"
    event["Event ID"] = event_id
    event["Host Name (Server)"] = computer
    event["Host Name"] = computer
    event["User Name"] = user
    if image:
        event["Process Name"] = image
        event["Image"] = image
    if command_line:
        event["Command Line"] = command_line
    if parent_image:
        event["Parent Process Name"] = parent_image
    if parent_command_line:
        event["Parent Command Line"] = parent_command_line
    if target_image:
        event["Target Image"] = target_image
    if source_image:
        event["Source Image"] = source_image
    if pipe_name:
        event["Pipe Name"] = pipe_name
    if query_name:
        event["Query Name"] = query_name
        event["DNS Query"] = query_name
    if target_filename:
        event["Target Filename"] = target_filename
    if destination_ip:
        event["Destination IP"] = destination_ip
    if destination_port not in ("", None):
        event["Destination Port"] = str(destination_port)

    if extra:
        event.update(extra)
    return event
