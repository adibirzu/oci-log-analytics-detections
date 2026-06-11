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

    # ── 2026 AiTM / token-abuse chain: phishing token replay into cloud APIs ──
    aitm_actions = [
        ("com.oraclecloud.consolesignon.login", "code-of-conduct-token-replay"),
        ("com.oraclecloud.identitycontrolplane.listusers", "token-abuse-list-users"),
        ("com.oraclecloud.identitycontrolplane.listgroups", "token-abuse-list-groups"),
        ("com.oraclecloud.objectstorage.listbuckets", "token-abuse-list-buckets"),
        ("com.oraclecloud.objectstorage.listobjects", "finance-exports"),
        ("com.oraclecloud.objectstorage.getobject", "finance-exports/payroll-may-2026.csv"),
        ("com.oraclecloud.identitycontrolplane.createauthtoken", "backup-access-token"),
    ]
    for i, (event_type, resource_name) in enumerate(aitm_actions):
        event = oci_audit_event(
            event_type,
            user="codeofconduct-reader@corp.example.com",
            ip="203.0.113.88",
            resource_name=resource_name,
            response_payload={
                "traceId": AITM_TRACE_ID,
                "clientApp": "legacy-browser-session",
                "authContext": "aitm-token-replay",
            },
            offset=1330 + i,
        )
        event["Trace ID"] = AITM_TRACE_ID
        event["Attack Stage"] = "aitm_token_abuse"
        event["Threat Name"] = "AiTM Token Replay"
        events.append(event)

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

    # ── Web-to-cloud threat hunt: compromised service identity abusing Object Storage ──
    web_to_cloud_actions = [
        (
            "com.oraclecloud.objectstorage.listbuckets",
            WEB_TO_CLOUD_BUCKET,
            {"compartmentId": COMPARTMENT_ID, "traceId": WEB_TO_CLOUD_TRACE_ID},
        ),
        (
            "com.oraclecloud.objectstorage.listobjects",
            f"{WEB_TO_CLOUD_BUCKET}/exports",
            {"bucketName": WEB_TO_CLOUD_BUCKET, "prefix": "exports/", "traceId": WEB_TO_CLOUD_TRACE_ID},
        ),
        (
            "com.oraclecloud.objectstorage.getobject",
            f"{WEB_TO_CLOUD_BUCKET}/{WEB_TO_CLOUD_EXFIL_OBJECT}",
            {
                "bucketName": WEB_TO_CLOUD_BUCKET,
                "objectName": WEB_TO_CLOUD_EXFIL_OBJECT,
                "bytesReturned": 73400320,
                "traceId": WEB_TO_CLOUD_TRACE_ID,
            },
        ),
        (
            "com.oraclecloud.objectstorage.createpreauthenticatedrequest",
            f"{WEB_TO_CLOUD_BUCKET}/{WEB_TO_CLOUD_EXFIL_OBJECT}:read-only-par",
            {
                "bucketName": WEB_TO_CLOUD_BUCKET,
                "objectName": WEB_TO_CLOUD_EXFIL_OBJECT,
                "accessType": "ObjectRead",
                "traceId": WEB_TO_CLOUD_TRACE_ID,
            },
        ),
    ]
    for i, (event_type, resource_name, response_payload) in enumerate(web_to_cloud_actions):
        event = oci_audit_event(
            event_type,
            user=WEB_TO_CLOUD_COMPROMISED_USER,
            ip=WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP,
            resource_name=resource_name,
            response_payload=response_payload,
            offset=1500 + i,
        )
        event["Trace ID"] = WEB_TO_CLOUD_TRACE_ID
        event["Attack Stage"] = "cloud_data_access"
        events.append(event)

    return events
