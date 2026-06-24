"""Auto-extracted from generate_test_logs.py — windows sysmon synthetic events.

Behavior-preserving split: function bodies are unchanged. Shared constants and
helpers live in ``testlogs.common`` and are imported via star import.
"""
import json
import ntpath
import os
import random
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testlogs.common import *  # noqa: F401,F403


def sysmon_event(event_id, image, command_line, host=None, user=None,
                 parent_image="C:\\Windows\\explorer.exe",
                 target_image=None, target_filename=None, target_object=None,
                 granted_access=None, dest_hostname=None, dest_ip=None,
                 pipe_name=None, msg=None, offset=0, **extra):
    """Generate a Windows Sysmon Event 1 style JSON event.

    Uses OCI Log Analytics field names (e.g. 'Process Name', 'Command Line')
    so that the Upload API auto-maps them to LA fields for query/dashboard use.
    Also retains Sysmon-native names (Image, CommandLine) for parser compatibility.
    """
    if host is None:
        host = random.choice(WINDOWS_HOSTS)
    if user is None:
        user = random.choice(WINDOWS_USERS)
    event_time = ts(offset)
    current_directory = ntpath.dirname(image) + "\\"
    original_name = ntpath.basename(image)
    parent_cmd = extra.pop("ParentCommandLine", ntpath.basename(parent_image))
    event = {
        # OCI Log Analytics mapped fields (used by OCL queries)
        "Event ID": event_id,
        "Process Name": image,
        "Command Line": command_line,
        "Parent Process Name": parent_image,
        "Parent Command Line": parent_cmd,
        "Host Name (Server)": host,
        "Original File Name": original_name,
        "Integrity Level": random.choice(["System", "High", "Medium"]),
        "Logon ID": hex(random.randint(0x3E4, 0xFFF)),
        "Terminal Session ID": random.choice([0, 1, 2, 3, 10]),
        # Sysmon-native fields (for raw reference / parser fallback)
        "EventID": event_id,
        "TimeCreated": event_time,
        "UtcTime": event_time,
        "Computer": host,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider": "Microsoft-Windows-Sysmon",
        "User": user,
        "ProcessId": random.randint(100, 9999),
        "ProcessGuid": windows_guid(),
        "Image": image,
        "CommandLine": command_line,
        "CurrentDirectory": current_directory,
        "FileVersion": "10.0.0.0",
        "Description": f"{original_name} process",
        "Product": "Microsoft Windows Operating System",
        "Company": "Microsoft Corporation",
        "OriginalFileName": original_name,
        "Hashes": (
            f"SHA1={(uuid.uuid4().hex + uuid.uuid4().hex)[:40].upper()},"
            f"MD5={uuid.uuid4().hex.upper()},"
            f"SHA256={(uuid.uuid4().hex + uuid.uuid4().hex)[:64].upper()}"
        ),
        "LogonGuid": windows_guid(),
        "LogonId": hex(random.randint(0x3E4, 0xFFF)),
        "TerminalSessionId": random.choice([0, 1, 2, 3, 10]),
        "IntegrityLevel": random.choice(["System", "High", "Medium"]),
        "ParentProcessGuid": windows_guid(),
        "ParentProcessId": random.randint(100, 9999),
        "ParentImage": parent_image,
        "ParentCommandLine": parent_cmd,
        "SourceImage": image,
        "TargetImage": target_image or "",
        "TargetFilename": target_filename or "",
        "TargetObject": target_object or "",
        "GrantedAccess": granted_access or "",
        "DestinationHostname": dest_hostname or "",
        "DestinationIp": dest_ip or "",
        "PipeName": pipe_name or "",
        # OCI LA mapped duplicates
        "Source Process": image,
        "Target Process": target_image or "",
        "Target Filename": target_filename or "",
        "Target Object": target_object or "",
        "Granted Access": granted_access or "",
        "Destination Hostname": dest_hostname or "",
        "Destination IP": dest_ip or "",
        "Pipe Name": pipe_name or "",
        "msg": msg or f"Sysmon event {event_id}: {ntpath.basename(image)}",
    }
    event.update(extra)
    return event


