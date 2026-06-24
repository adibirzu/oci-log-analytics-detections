"""Auto-extracted from generate_test_logs.py — oci audit synthetic events.

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
        user = ("<DEMO_USER_SUPPLIED_OCID>", user, "natv")
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
        tenant_id="<DEMO_TENANCY_OCID>",
        resource_name=resource_name,
        resource_id=f"<DEMO_RESOURCE_OCID_{uuid.uuid4().hex[:8]}>",
        user_agent="Oracle-JavaSDK/2.0 (test-simulation)",
        response_status=status,
        response_payload=response_payload,
    )
    # Preserve the legacy Oracle ingest envelope so existing OCI LA parsers
    # that key on ``oracle.compartmentid``/``oracle.ingestedtime`` keep working.
    event["oracle"] = {
        "compartmentid": COMPARTMENT_ID,
        "ingestedtime": ts(offset),
        "tenantid": "<DEMO_TENANCY_OCID>",
    }
    # OCI LA OCI Audit native parser exposes the parsed Status field as the
    # raw HTTP status by default ("200", "404"), but several detection queries
    # expect the operator-friendly form ("Success" / "Failure"). Override the
    # ``Status`` parallel column so both forms are queryable.
    if str(status).startswith("2"):
        event["Status"] = "Success"
    elif str(status).startswith(("4", "5")):
        event["Status"] = "Failure"
    event["Resource Name"] = resource_name
    event["Resource ID"] = event.get("data", {}).get("resourceId", "")
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
            principal_id="<DEMO_USER_ADMIN_OCID>",
            principal_name="admin@corp.example.com",
            auth_type="natv",
            ip_address=random.choice(SUSPICIOUS_IPS),
            compartment_id=COMPARTMENT_ID,
            compartment_name="security-test",
            tenant_id="<DEMO_TENANCY_OCID>",
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
            "tenantid": "<DEMO_TENANCY_OCID>",
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

    # ── Audit Configuration Retention Reduced (T1562.008 / T1070) ──
    # Emit explicit retentionPeriodDays state-change so the hunting query
    # "oci_audit_configuration_retention_reduced" matches against
    # 'Original Log Content' like '*retentionPeriodDays*'. Principals reuse
    # the existing OCI_USERS synthetic identity pool — no new OCID-shaped
    # strings are introduced in this file.
    from schemas import build_oci_audit_event as _build_audit

    rogue_admin = OCI_USERS[3]        # rogue-admin@corp.example.com
    compromised_svc = OCI_USERS[4]    # compromised-svc@corp.example.com
    dev_ops_user = OCI_USERS[2]       # dev-ops@corp.example.com
    retention_tenant_id = oci_audit_event(
        "com.oraclecloud.audit.updateconfiguration", offset=1111
    )["data"]["identity"]["tenantId"]  # reuse the synthetic tenant placeholder

    retention_changes = [
        (365, 30,  rogue_admin),
        (365, 14,  compromised_svc),
        (180, 7,   dev_ops_user),
        (90,  1,   rogue_admin),
    ]
    for i, (prev_days, new_days, host_user) in enumerate(retention_changes):
        ev = _build_audit(
            "com.oraclecloud.audit.updateconfiguration",
            event_time=ts(1112 + i),
            principal_id=host_user[0],
            principal_name=host_user[1],
            auth_type=host_user[2],
            ip_address=random.choice(SUSPICIOUS_IPS),
            compartment_id=COMPARTMENT_ID,
            compartment_name="security-test",
            tenant_id=retention_tenant_id,
            resource_name="audit-config",
            request_parameters={"retentionPeriodDays": new_days, "isEnabled": True},
            response_payload={"retentionPeriodDays": new_days, "isEnabled": True, "compartmentId": COMPARTMENT_ID},
            state_previous={"retentionPeriodDays": prev_days, "isEnabled": True},
            state_current={"retentionPeriodDays": new_days, "isEnabled": True},
            response_status="200",
        )
        ev["oracle"] = {
            "compartmentid": COMPARTMENT_ID,
            "ingestedtime": ts(1112 + i),
            "tenantid": retention_tenant_id,
        }
        ev["Status"] = "Success"
        ev["Resource Name"] = "audit-config"
        ev["Resource ID"] = ev.get("data", {}).get("resourceId", "")
        # Surface raw JSON so 'Original Log Content' parser exposes retentionPeriodDays
        ev["Original Log Content"] = json.dumps(ev.get("data", {}))
        events.append(ev)

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

    from testlogs.oci_audit_expansion import append_oci_audit_expansion_events

    return append_oci_audit_expansion_events(events)
