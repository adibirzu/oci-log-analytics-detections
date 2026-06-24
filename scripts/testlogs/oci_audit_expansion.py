"""OCI Audit synthetic expansion and hunting event appenders."""

import random

from testlogs.common import *  # noqa: F401,F403
from testlogs.oci_audit import oci_audit_event


def append_oci_audit_expansion_events(events):
    """Append batch-expansion and aggregation-focused OCI Audit events."""
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

    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.bastion.createsession",
            resource_name=f"bastion-ssh-session-{i}",
            offset=1220+i
        ))

    for i in range(2):
        events.append(oci_audit_event(
            "com.oraclecloud.computeapi.createinstanceconsoleconnection",
            resource_name="prod-instance-console",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=1230+i
        ))

    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.ons.createsubscription",
            resource_name=f"alert-subscription-{i}",
            offset=1240+i
        ))

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

    for i in range(3):
        events.append(oci_audit_event(
            "com.oraclecloud.identitycontrolplane.createcustomersecretkey",
            resource_name="s3-compat-key",
            ip=random.choice(SUSPICIOUS_IPS),
            offset=1260+i
        ))

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
            user="rogue-admin@corp.example.com",
            ip="194.5.249.7",
            resource_name=f"rapid-change-{i}",
            offset=1340+i
        ))

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
