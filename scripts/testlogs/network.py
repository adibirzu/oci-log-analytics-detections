"""Auto-extracted from generate_test_logs.py — VCN flow + Network Firewall synthetic events.

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


def vcn_flow_event(src_ip, dst_ip, src_port, dst_port, protocol="6", action="ACCEPT",
                   bytes_out=0, bytes_in=0, packets_out=1, packets_in=1,
                   flow_id=None, vnic_id=None, subnet_id=None, trace_id=None,
                   stage=None, offset=0):
    """Generate an OCI VCN Flow Log-shaped record with SOC parser aliases."""
    event_time = ts(offset)
    start_time = iso_to_epoch_seconds(event_time)
    end_time = start_time + 60
    flow_id = flow_id or f"flow-{uuid.uuid4().hex[:16]}"
    vnic_id = vnic_id or f"<DEMO_VNIC_OCID_{uuid.uuid4().hex[:8]}>"
    subnet_id = subnet_id or f"<DEMO_SUBNET_OCID_{uuid.uuid4().hex[:8]}>"
    data = {
        "version": "1",
        "vcnId": f"<DEMO_VCN_OCID_{uuid.uuid4().hex[:8]}>",
        "subnetId": subnet_id,
        "vnicId": vnic_id,
        "flowId": flow_id,
        "flowid": flow_id,
        "sourceAddress": src_ip,
        "destinationAddress": dst_ip,
        "sourcePort": int(src_port),
        "destinationPort": int(dst_port),
        "srcaddr": src_ip,
        "dstaddr": dst_ip,
        "srcport": int(src_port),
        "dstport": int(dst_port),
        "protocol": str(protocol),
        "action": action,
        "status": "OK",
        "startTime": start_time,
        "endTime": end_time,
        "bytesOut": int(bytes_out),
        "bytesIn": int(bytes_in),
        "packetsOut": int(packets_out),
        "packetsIn": int(packets_in),
    }
    return {
        "datetime": start_time * 1000,
        "id": str(uuid.uuid4()),
        "oracle": {
            "compartmentid": COMPARTMENT_ID,
            "ingestedtime": event_time,
            "loggroupid": "<DEMO_LOG_GROUP_OCID>",
            "logid": "<DEMO_VCN_FLOW_LOG_OCID>",
            "tenantid": "<DEMO_TENANCY_OCID>",
        },
        "regionId": "us-phoenix-1",
        "source": "vcn-flow-logs",
        "specversion": "1.0",
        "time": event_time,
        "type": "com.oraclecloud.vcn.flowlogs.DataEvent",
        "data": data,
        "Log Source": "SOC VCN Flow Logs",
        "Trace ID": trace_id or "",
        "Attack Stage": stage or "",
        "Source IP": src_ip,
        "Destination IP": dst_ip,
        "Source Port": str(src_port),
        "Destination Port": str(dst_port),
        "Protocol": str(protocol),
        "Action": action,
        "Network Action": action,
        "Bytes Sent": str(bytes_out),
        "Bytes Received": str(bytes_in),
        "Packets": str(int(packets_out) + int(packets_in)),
        "Flow ID": flow_id,
        "msg": f"VCN Flow {action}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
    }


def generate_splunk_migration_vcn_flow_events():
    """Return deterministic threshold-boundary fixtures for the Splunk migration alert."""
    events = []
    for source_ip, rejected_count in (("203.0.113.110", 101), ("203.0.113.111", 100)):
        for index in range(rejected_count):
            events.append(vcn_flow_event(
                source_ip,
                "192.0.2.80",
                40000 + index,
                443,
                action="REJECT",
                flow_id=f"flow-splunk-rejected-{source_ip.rsplit('.', 1)[-1]}-{index:03d}",
                stage="splunk_migration_fixture",
                offset=220 + index,
            ))
    return events


def generate_vcn_flow_events():
    """Generate VCN Flow Log records for ingress, C2, lateral movement, and exfil."""
    events = []

    # Entry request from the internet-facing path into the application subnet.
    events.append(vcn_flow_event(
        WEB_TO_CLOUD_ATTACKER_IP,
        WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP,
        54321,
        443,
        bytes_out=8192,
        bytes_in=2140,
        packets_out=18,
        packets_in=12,
        flow_id="flow-w2c-entry-001",
        trace_id=WEB_TO_CLOUD_TRACE_ID,
        stage="entry_point",
        offset=126,
    ))

    # Instance metadata and service gateway traffic from the compromised host.
    events.append(vcn_flow_event(
        WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP,
        "169.254.169.254",
        43312,
        80,
        bytes_out=2048,
        bytes_in=4096,
        packets_out=6,
        packets_in=8,
        flow_id="flow-w2c-metadata-001",
        trace_id=WEB_TO_CLOUD_TRACE_ID,
        stage="credential_access",
        offset=127,
    ))
    events.append(vcn_flow_event(
        WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP,
        "134.70.120.10",
        43610,
        443,
        bytes_out=62914560,
        bytes_in=16384,
        packets_out=4200,
        packets_in=640,
        flow_id="flow-w2c-objectstorage-001",
        trace_id=WEB_TO_CLOUD_TRACE_ID,
        stage="cloud_data_access",
        offset=128,
    ))

    # Repeated outbound C2/exfil path to make frequency and byte-volume widgets visible.
    for i, bytes_out in enumerate([2048, 4096, 8192, 73400320]):
        events.append(vcn_flow_event(
            WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP,
            WEB_TO_CLOUD_C2_IP,
            44000 + i,
            443,
            bytes_out=bytes_out,
            bytes_in=2048,
            packets_out=18 + i * 20,
            packets_in=10,
            flow_id=f"flow-w2c-c2-{i + 1:03d}",
            trace_id=WEB_TO_CLOUD_TRACE_ID,
            stage="exfiltration" if bytes_out > 50000000 else "c2_beacon",
            offset=129 + i,
        ))

    # ClickFix/CrashFix compromise: payload callbacks followed by staged exfil.
    clickfix_flow_specs = [
        (CLICKFIX_COMPROMISED_PRIVATE_IP, CLICKFIX_C2_IP, 46000, 443, 16384, 4096, "command_and_control"),
        (CLICKFIX_COMPROMISED_PRIVATE_IP, "203.0.113.202", 46010, 443, 31457280, 2048, "exfiltration"),
    ]
    for i, (src_ip, dst_ip, src_port, dst_port, bytes_out, bytes_in, stage) in enumerate(clickfix_flow_specs):
        events.append(vcn_flow_event(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            bytes_out=bytes_out,
            bytes_in=bytes_in,
            packets_out=32 if stage == "command_and_control" else 2800,
            packets_in=20,
            flow_id=f"flow-clickfix-2026-{i + 1:03d}",
            trace_id=CLICKFIX_TRACE_ID,
            stage=stage,
            offset=138 + i,
        ))

    # FreeLabFriday port-knocking lab sequence: valid 7000 -> 8000 -> 9000
    # knock followed by SSH, plus a failing attacker with the wrong order.
    for i, port in enumerate([7000, 8000, 9000, 22]):
        events.append(vcn_flow_event(
            "198.51.100.7",
            "192.0.2.55",
            54321 + i,
            port,
            action="ACCEPT",
            bytes_out=60 if port != 22 else 4200,
            bytes_in=40 if port != 22 else 5200,
            packets_out=1 if port != 22 else 18,
            packets_in=1 if port != 22 else 16,
            flow_id=f"flow-flf-port-knock-valid-{i + 1:02d}",
            trace_id="trace_flf_port_knock_001",
            stage="port_knock" if port != 22 else "ssh_opened",
            offset=145 + i,
        ))
    for i, port in enumerate([7000, 9000, 8000, 22]):
        events.append(vcn_flow_event(
            "198.51.100.12",
            "192.0.2.55",
            55321 + i,
            port,
            action="REJECT",
            bytes_out=0,
            bytes_in=0,
            packets_out=1,
            packets_in=0,
            flow_id=f"flow-flf-port-knock-failed-{i + 1:02d}",
            trace_id="trace_flf_port_knock_failed_001",
            stage="port_knock_failed",
            offset=151 + i,
        ))

    # Baseline accepted and rejected flows for contrast on the dashboard.
    for i in range(8):
        events.append(vcn_flow_event(
            random.choice(CORPORATE_IPS),
            random.choice(["10.0.1.20", "10.0.2.30", "10.0.3.40"]),
            random.randint(49152, 65535),
            random.choice([80, 443, 1521, 5432]),
            bytes_out=random.randint(1200, 24000),
            bytes_in=random.randint(900, 12000),
            packets_out=random.randint(3, 30),
            packets_in=random.randint(3, 25),
            flow_id=f"flow-baseline-{i:03d}",
            stage="baseline",
            offset=170 + i,
        ))
    for i in range(4):
        events.append(vcn_flow_event(
            random.choice(SUSPICIOUS_IPS),
            WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP,
            random.randint(49152, 65535),
            random.choice([22, 3389, 8080, 9200]),
            action="REJECT",
            bytes_out=0,
            bytes_in=0,
            packets_out=1,
            packets_in=0,
            flow_id=f"flow-rejected-scan-{i:03d}",
            stage="reconnaissance",
            offset=185 + i,
        ))

    events.extend(generate_splunk_migration_vcn_flow_events())
    return events


def network_firewall_event(log_type, src_ip, dst_ip, src_port, dst_port,
                           protocol="tcp", action="allow", rule_name="allow-web-egress",
                           app="ssl", bytes_sent=0, bytes_received=0,
                           threat_name="", threat_category="", severity="",
                           trace_id=None, stage=None, offset=0):
    """Generate an OCI Network Firewall traffic/threat log-shaped record."""
    event_time = ts(offset)
    session_id = random.randint(1000000000, 9999999999)
    data = {
        "log_type": log_type,
        "sessionid": str(session_id),
        "src": src_ip,
        "dst": dst_ip,
        "sport": str(src_port),
        "dport": str(dst_port),
        "proto": protocol,
        "action": action,
        "rule": rule_name,
        "app": app,
        "bytes": str(int(bytes_sent) + int(bytes_received)),
        "bytes_sent": str(bytes_sent),
        "bytes_received": str(bytes_received),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": str(src_port),
        "dst_port": str(dst_port),
        "threatid": threat_name,
        "threat_name": threat_name,
        "category": threat_category,
        "severity": severity,
        "direction": "client-to-server",
        "src_zone": "app-subnet",
        "dst_zone": "internet",
    }
    return {
        "datetime": iso_to_epoch_seconds(event_time) * 1000,
        "logContent": {
            "data": data,
            "id": str(uuid.uuid4()),
            "oracle": {
                "compartmentid": COMPARTMENT_ID,
                "ingestedtime": event_time,
                "loggroupid": "<DEMO_LOG_GROUP_OCID>",
                "logid": "<DEMO_NETWORK_FIREWALL_LOG_OCID>",
                "tenantid": "<DEMO_TENANCY_OCID>",
            },
            "source": "network-firewall",
            "specversion": "1.0",
            "time": event_time,
            "type": "com.oraclecloud.networkfirewall.logs",
        },
        "Log Source": "SOC Network Firewall Logs",
        "Trace ID": trace_id or "",
        "Attack Stage": stage or "",
        "Log Type": log_type,
        "Action": action,
        "Network Action": action,
        "Source IP": src_ip,
        "Destination IP": dst_ip,
        "Source Port": str(src_port),
        "Destination Port": str(dst_port),
        "Protocol": protocol,
        "Bytes Sent": str(bytes_sent),
        "Bytes Received": str(bytes_received),
        "Firewall Rule": rule_name,
        "Threat Name": threat_name,
        "Threat Category": threat_category,
        "Severity Level": severity,
        "Session ID": str(session_id),
        "msg": f"Network Firewall {log_type} {action}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
    }


def generate_network_firewall_events():
    """Generate OCI Network Firewall logs for C2, exfiltration, and blocked scans."""
    events = []

    for i in range(3):
        events.append(network_firewall_event(
            "traffic",
            WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP,
            WEB_TO_CLOUD_C2_IP,
            45000 + i,
            443,
            action="allow",
            rule_name="allow-app-egress-tls",
            app="ssl",
            bytes_sent=2048 + i * 1024,
            bytes_received=1536,
            trace_id=WEB_TO_CLOUD_TRACE_ID,
            stage="c2_beacon",
            offset=132 + i,
        ))

    events.append(network_firewall_event(
        "threat",
        WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP,
        WEB_TO_CLOUD_C2_IP,
        45010,
        443,
        action="alert",
        rule_name="inspect-app-egress",
        app="ssl",
        bytes_sent=73400320,
        bytes_received=2048,
        threat_name="Suspicious Data Exfiltration",
        threat_category="data-theft",
        severity="critical",
        trace_id=WEB_TO_CLOUD_TRACE_ID,
        stage="exfiltration",
        offset=136,
    ))

    events.append(network_firewall_event(
        "threat",
        WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP,
        "169.254.169.254",
        45100,
        80,
        action="alert",
        rule_name="detect-metadata-service-access",
        app="web-browsing",
        bytes_sent=2048,
        bytes_received=4096,
        threat_name="Cloud Metadata Service Access",
        threat_category="credential-access",
        severity="high",
        trace_id=WEB_TO_CLOUD_TRACE_ID,
        stage="credential_access",
        offset=137,
    ))

    events.append(network_firewall_event(
        "traffic",
        CLICKFIX_COMPROMISED_PRIVATE_IP,
        CLICKFIX_C2_IP,
        46100,
        443,
        action="allow",
        rule_name="allow-workstation-egress-tls",
        app="ssl",
        bytes_sent=16384,
        bytes_received=8192,
        trace_id=CLICKFIX_TRACE_ID,
        stage="command_and_control",
        offset=138,
    ))
    events.append(network_firewall_event(
        "threat",
        CLICKFIX_COMPROMISED_PRIVATE_IP,
        "203.0.113.202",
        46110,
        443,
        action="alert",
        rule_name="inspect-workstation-egress",
        app="ssl",
        bytes_sent=31457280,
        bytes_received=2048,
        threat_name="ClickFix Data Exfiltration",
        threat_category="data-theft",
        severity="critical",
        trace_id=CLICKFIX_TRACE_ID,
        stage="exfiltration",
        offset=139,
    ))

    # FreeLabFriday port knocking evidence.
    for i, port in enumerate([7000, 8000, 9000, 22]):
        events.append(network_firewall_event(
            "traffic",
            "198.51.100.7",
            "192.0.2.55",
            54321 + i,
            port,
            action="allow",
            rule_name="flf-port-knock-stateful-open" if port == 22 else "flf-port-knock-observed",
            app="ssh" if port == 22 else "unknown-tcp",
            bytes_sent=64 if port != 22 else 4200,
            bytes_received=40 if port != 22 else 5200,
            trace_id="trace_flf_port_knock_001",
            stage="port_knock" if port != 22 else "ssh_opened",
            offset=145 + i,
        ))
    for i, port in enumerate([7000, 9000, 8000, 22]):
        events.append(network_firewall_event(
            "traffic",
            "198.51.100.12",
            "192.0.2.55",
            55321 + i,
            port,
            action="deny",
            rule_name="flf-port-knock-wrong-sequence",
            app="unknown-tcp",
            bytes_sent=0,
            bytes_received=0,
            trace_id="trace_flf_port_knock_failed_001",
            stage="port_knock_failed",
            offset=151 + i,
        ))

    for i in range(6):
        events.append(network_firewall_event(
            "traffic",
            random.choice(CORPORATE_IPS),
            random.choice(["140.82.112.14", "142.250.80.46", "13.107.42.14"]),
            random.randint(49152, 65535),
            443,
            action="allow",
            rule_name="allow-enterprise-egress",
            app="ssl",
            bytes_sent=random.randint(1200, 24000),
            bytes_received=random.randint(1200, 48000),
            stage="baseline",
            offset=190 + i,
        ))
    for i in range(4):
        events.append(network_firewall_event(
            "traffic",
            random.choice(SUSPICIOUS_IPS),
            WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP,
            random.randint(49152, 65535),
            random.choice([22, 3389, 9200, 8080]),
            action="deny",
            rule_name="deny-internet-admin-ports",
            app="unknown-tcp",
            bytes_sent=0,
            bytes_received=0,
            stage="reconnaissance",
            offset=205 + i,
        ))

    return events
