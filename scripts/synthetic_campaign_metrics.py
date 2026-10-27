"""Synthetic storyline metrics event family.

Explicit inputs preserve deterministic identities and caller-controlled event order.
"""
from __future__ import annotations

from typing import Any


def build_multicloud_metrics(
    *,
    rmm_relay_ip: str,
    aws_region: str,
    azure_region: str,
    d4_ts2: str,
    d5_ts3: str,
    d6_ts1: str,
    d7_ts1: str,
    d7_ts2: str,
    d7_ts3: str,
    day_traces: dict[int, str],
    gcp_region: str,
    oci_region: str,
) -> list[dict[str, Any]]:
    """Emit this event family using the supplied identities and timeline."""
    # 7. Multi-Cloud & AC-Hunter OCI Monitoring Custom Metric Streams
    multicloud_metrics = [
        {
            "namespace": "octo_multicloud_ops",
            "secondary_namespace": "oci_observability_demo",
            "name": "multicloud.aws.cloudtrail_suspicious_api_calls",
            "timestamp": d5_ts3,
            "value": 14.0,
            "dimensions": {"cloud_provider": "AWS", "region": aws_region, "c2_ip": "198.51.100.214", "trace_id": day_traces[5]},
        },
        {
            "namespace": "octo_multicloud_ops",
            "secondary_namespace": "oci_observability_demo",
            "name": "multicloud.azure.entra_sp_credential_modifications",
            "timestamp": d4_ts2,
            "value": 6.0,
            "dimensions": {"cloud_provider": "Azure", "region": azure_region, "c2_ip": rmm_relay_ip, "trace_id": day_traces[4]},
        },
        {
            "namespace": "octo_multicloud_ops",
            "secondary_namespace": "oci_observability_demo",
            "name": "multicloud.gcp.iam_and_firewall_drift_events",
            "timestamp": d6_ts1,
            "value": 9.0,
            "dimensions": {"cloud_provider": "GCP", "region": gcp_region, "c2_ip": "198.51.100.214", "trace_id": day_traces[6]},
        },
        {
            "namespace": "octo_multicloud_ops",
            "secondary_namespace": "oci_observability_demo",
            "name": "multicloud.oci.cross_csp_correlated_incidents",
            "timestamp": d7_ts3,
            "value": 4.0,
            "dimensions": {"cloud_provider": "OCI", "region": oci_region, "c2_ip": "198.51.100.214", "trace_id": day_traces[7]},
        },
        {
            "namespace": "octo_ac_hunter",
            "secondary_namespace": "oci_observability_demo",
            "name": "ac_hunter.rita_beacon_score_max",
            "timestamp": d7_ts2,
            "value": 96.4,
            "dimensions": {"host": "kingslanding", "c2_ip": "198.51.100.214", "port": "8443", "trace_id": day_traces[7]},
        },
        {
            "namespace": "octo_ac_hunter",
            "secondary_namespace": "oci_observability_demo",
            "name": "ac_hunter.long_connection_max_duration_sec",
            "timestamp": d7_ts2,
            "value": 28400.0,
            "dimensions": {"host": "kingslanding", "c2_ip": "198.51.100.214", "port": "8443", "trace_id": day_traces[7]},
        },
        {
            "namespace": "octo_ac_hunter",
            "secondary_namespace": "oci_observability_demo",
            "name": "ac_hunter.dns_tunnel_distinct_subdomains",
            "timestamp": d7_ts1,
            "value": 342.0,
            "dimensions": {"host": "kingslanding", "fqdn_zone": "exfil.c2-stage.example.net", "trace_id": day_traces[7]},
        },
        {
            "namespace": "octo_ac_hunter",
            "secondary_namespace": "oci_observability_demo",
            "name": "ac_hunter.composite_host_threat_score_max",
            "timestamp": d7_ts3,
            "value": 97.0,
            "dimensions": {"host": "kingslanding", "c2_ip": "198.51.100.214", "trace_id": day_traces[7]},
        },
    ]
    return multicloud_metrics
