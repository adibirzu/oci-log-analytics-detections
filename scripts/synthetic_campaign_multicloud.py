"""Synthetic storyline multicloud event family.

Explicit inputs preserve deterministic identities and caller-controlled event order.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from collections.abc import Mapping

if __package__:
    from .synthetic_campaign_common import (
        _deterministic_hex,
        _ip,
    )
else:
    from synthetic_campaign_common import (
        _deterministic_hex,
        _ip,
    )


@dataclass(frozen=True)
class MulticloudResult:
    aws_region: str
    azure_region: str
    gcp_region: str
    ip_goad_dc2: str
    multicloud_logs: list[dict[str, Any]]
    oci_region: str


def build_multicloud_events(
    *,
    rmm_relay_ip: str,
    corp_mail_domain: str,
    ctx: Mapping[str, str],
    d1_ts1: str,
    d2_ts1: str,
    d3_ts1: str,
    d4_ts2: str,
    d5_ts3: str,
    d6_ts1: str,
    d6_ts2: str,
    d7_ts2: str,
    day_traces: dict[int, str],
    guardian_adb: str,
    ip_goad_dc: str,
    ip_goad_pivot: str,
    ip_oke_node: str,
    ip_vcn_target: str,
    seed: str,
) -> MulticloudResult:
    """Emit this event family using the supplied identities and timeline."""
    # 5. Multi-Cloud (AWS CloudTrail OCSF, Azure Activity/Entra ID, GCP Cloud Audit, OCI Bridge) Correlated Logs
    aws_region = "-".join(("us", "east", "1"))
    azure_region = "west" + "europe"
    gcp_region = "-".join(("europe", "west3"))
    oci_region = ctx.get("OCI_REGION") or "-".join(("eu", "frankfurt", "1"))
    ip_goad_dc2 = _ip(192, 168, 56, 11)

    multicloud_logs: list[dict[str, Any]] = []
    multicloud_specs = [
        {
            "day": 1,
            "ts": d1_ts1,
            "cloud": "AWS",
            "region": aws_region,
            "service": "aws-cloudtrail-ocsf",
            "event_name": "AssumeRole",
            "event_type": "aws.cloudtrail.sts.AssumeRole",
            "user": "arn:aws:iam::901234567890:role/octo-multicloud-sync-role",
            "src_ip": "198.51.100.214",
            "dst_ip": ip_vcn_target,
            "resource": "arn:aws:iam::901234567890:role/octo-prod-secrets-reader",
            "status": "200",
            "ua": "Mozilla/5.0 (compatible; Nuclei/3.3.0; +https://projectdiscovery.io)",
            "msg": f"AWS_CLOUDTRAIL OCSF AssumeRole cross-account pivot in {aws_region} from 198.51.100.214 targeting octo-prod-secrets-reader",
        },
        {
            "day": 2,
            "ts": d2_ts1,
            "cloud": "AWS",
            "region": aws_region,
            "service": "aws-cloudtrail-ocsf",
            "event_name": "GetSecretValue",
            "event_type": "aws.cloudtrail.secretsmanager.GetSecretValue",
            "user": "arn:aws:sts::901234567890:assumed-role/octo-prod-secrets-reader/eks-pod-session",
            "src_ip": "198.51.100.214",
            "dst_ip": ip_oke_node,
            "resource": "octo/prod/crm-db-sync-credentials",
            "status": "200",
            "ua": "aws-sdk-go-v2/1.30.0",
            "msg": f"AWS_CLOUDTRAIL OCSF GetSecretValue harvested octo/prod/crm-db-sync-credentials in {aws_region} from 198.51.100.214",
        },
        {
            "day": 3,
            "ts": d3_ts1,
            "cloud": "Azure",
            "region": azure_region,
            "service": "azure-entra-activity",
            "event_name": "Add service principal credentials",
            "event_type": "Microsoft.AAD/servicePrincipals/credentials/action",
            "user": f"svc-multicloud-federation@{corp_mail_domain}",
            "src_ip": "198.51.100.214",
            "dst_ip": ip_goad_dc,
            "resource": "octo-azure-ad-federation-sp",
            "status": "200",
            "ua": "AzureCLI/2.64.0",
            "msg": f"AZURE_ACTIVITY Entra ID AuditLogs: Add service principal credentials on octo-azure-ad-federation-sp in {azure_region} from 198.51.100.214",
        },
        {
            "day": 4,
            "ts": d4_ts2,
            "cloud": "Azure",
            "region": azure_region,
            "service": "azure-entra-activity",
            "event_name": "NetworkSecurityGroupRuleUpdate",
            "event_type": "Microsoft.Network/networkSecurityGroups/securityRules/write",
            "user": f"svc-multicloud-federation@{corp_mail_domain}",
            "src_ip": rmm_relay_ip,
            "dst_ip": ip_goad_pivot,
            "resource": "octo-aks-spoke-nsg/allow-c2-relay-7844",
            "status": "200",
            "ua": "Azure-SDK-For-Python/network-mgmt",
            "msg": f"AZURE_ACTIVITY NetworkSecurityGroupRuleUpdate opened port 7844 on octo-aks-spoke-nsg in {azure_region} for RMM relay {rmm_relay_ip}",
        },
        {
            "day": 5,
            "ts": d5_ts3,
            "cloud": "AWS",
            "region": aws_region,
            "service": "aws-cloudtrail-ocsf",
            "event_name": "ModifySecurityGroupRules",
            "event_type": "aws.cloudtrail.ec2.ModifySecurityGroupRules",
            "user": "arn:aws:sts::901234567890:assumed-role/octo-prod-secrets-reader/eks-pod-session",
            "src_ip": "198.51.100.214",
            "dst_ip": ip_vcn_target,
            "resource": "sg-0a91bc82de4410f92",
            "status": "200",
            "ua": "aws-cli/2.17.0",
            "msg": f"AWS_CLOUDTRAIL OCSF ModifySecurityGroupRules opened egress 8443 on sg-0a91bc82de4410f92 in {aws_region} to 198.51.100.214",
        },
        {
            "day": 5,
            "ts": d5_ts3,
            "cloud": "GCP",
            "region": gcp_region,
            "service": "gcp-cloud-audit",
            "event_name": "SetIamPolicy",
            "event_type": "google.iam.admin.v1.SetIamPolicy",
            "user": f"gcp-workload-bridge@{corp_mail_domain}",
            "src_ip": "198.51.100.214",
            "dst_ip": ip_vcn_target,
            "resource": "projects/octo-multicloud-prod/roles/owner",
            "status": "200",
            "ua": "google-cloud-sdk gcloud/492.0.0",
            "msg": f"GCP_AUDIT SetIamPolicy granted roles/owner to rogue workload identity in {gcp_region} from 198.51.100.214",
        },
        {
            "day": 6,
            "ts": d6_ts1,
            "cloud": "GCP",
            "region": gcp_region,
            "service": "gcp-cloud-audit",
            "event_name": "compute.firewalls.patch",
            "event_type": "v1.compute.firewalls.patch",
            "user": f"gcp-workload-bridge@{corp_mail_domain}",
            "src_ip": "192.0.2.119",
            "dst_ip": ip_vcn_target,
            "resource": "projects/octo-multicloud-prod/global/firewalls/allow-egress-8443",
            "status": "200",
            "ua": "google-api-python-client/2.143.0",
            "msg": f"GCP_AUDIT compute.firewalls.patch permitted TCP/8443 egress in {gcp_region} for 192.0.2.119 and 198.51.100.214",
        },
        {
            "day": 6,
            "ts": d6_ts2,
            "cloud": "OCI",
            "region": oci_region,
            "service": "oci-multicloud-federation",
            "event_name": "GenerateAutonomousDatabaseWallet",
            "event_type": "com.oraclecloud.autonomousdatabase.generateautonomousdatabasewallet",
            "user": f"contractor.ops@{corp_mail_domain}",
            "src_ip": "203.0.113.88",
            "dst_ip": ip_vcn_target,
            "resource": guardian_adb,
            "status": "200",
            "ua": "OCI-Python-SDK/2.126.0 (screenconnect-relay)",
            "msg": f"OCI_AUDIT GenerateAutonomousDatabaseWallet cross-CSP identity pivot from 203.0.113.88 targeting {guardian_adb} in {oci_region}",
        },
        {
            "day": 7,
            "ts": d7_ts2,
            "cloud": "GCP",
            "region": gcp_region,
            "service": "gcp-cloud-audit",
            "event_name": "storage.objects.get",
            "event_type": "storage.objects.get",
            "user": f"gcp-workload-bridge@{corp_mail_domain}",
            "src_ip": "192.0.2.119",
            "dst_ip": "198.51.100.214",
            "resource": "projects/octo-multicloud-prod/buckets/octo-analytics-export/customer_pii_dump.parquet",
            "status": "200",
            "ua": "python-oracledb-agentic-probe/1.4",
            "msg": f"GCP_AUDIT storage.objects.get bulk PII staging export in {gcp_region} from 192.0.2.119 correlated with 198.51.100.214",
        },
    ]
    for spec in multicloud_specs:
        d_num = spec["day"]
        for log_source_name in ("SOC Multicloud Health Logs", "SOC Application Logs"):
            multicloud_logs.append({
                "time": spec["ts"],
                "timestamp": spec["ts"],
                "day": d_num,
                "stage_id": f"STORYLINE-DAY-0{d_num}",
                "record_category": "multicloud_security_telemetry",
                "Log Source": log_source_name,
                "Cloud Provider": spec["cloud"],
                "Cloud Region": spec["region"],
                "Service Name": spec["service"],
                "Host Name": f"{spec['service']}-{spec['region']}",
                "Event Name": spec["event_name"],
                "Event Type": spec["event_type"],
                "Action": spec["event_name"],
                "User": spec["user"],
                "User Name": spec["user"],
                "Principal Name": spec["user"],
                "Source IP": spec["src_ip"],
                "Client IP": spec["src_ip"],
                "Destination IP": spec["dst_ip"],
                "Destination Port": "8443" if spec["src_ip"] == "198.51.100.214" else "7844",
                "Resource Name": spec["resource"],
                "Status": spec["status"],
                "Response Code": spec["status"],
                "User Agent": spec["ua"],
                "MITRE Technique ID": "T1078.004",
                "MITRE Tactic": "Defense Evasion",
                "Trace ID": day_traces[d_num],
                "Span ID": _deterministic_hex(seed, f"mc-span-{spec['cloud']}-{d_num}-{log_source_name[:6]}", 16),
                "msg": spec["msg"],
            })
    return MulticloudResult(
        aws_region=aws_region,
        azure_region=azure_region,
        gcp_region=gcp_region,
        ip_goad_dc2=ip_goad_dc2,
        multicloud_logs=multicloud_logs,
        oci_region=oci_region,
    )
