"""Synthetic storyline background event family.

Explicit inputs preserve deterministic identities and caller-controlled event order.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

if __package__:
    from .synthetic_campaign_common import (
        _deterministic_hex,
        _format_iso_utc,
    )
else:
    from synthetic_campaign_common import (
        _deterministic_hex,
        _format_iso_utc,
    )


def add_background_events(
    *,
    background_logs: list[dict[str, Any]],
    base_date: dt.date,
    corp_mail_domain: str,
    guardian_adb: str,
    ip_crm_sync: str,
    ip_devops: str,
    ip_iam_sa: str,
    ip_oke_node: str,
    observeai_adb: str,
    prefix: str,
    seed: str,
) -> None:
    """Emit this event family using the supplied identities and timeline."""
    # 1. Generate normal background service tasks across all 7 days at varied hours & minutes
    for day_idx in range(7):
        day_num = day_idx + 1
        current_date = base_date + dt.timedelta(days=day_idx)
        bg_trace = _deterministic_hex(seed, f"bg-day-{day_num:02d}", 32)

        # (a) Automated DB backup (02:15 + offset)
        t_backup = dt.datetime.combine(
            current_date, dt.time(2, 15 + (day_idx * 4) % 35, (day_idx * 13) % 60), tzinfo=dt.timezone.utc
        )
        ts_backup = _format_iso_utc(t_backup)
        background_logs.append({
            "time": ts_backup,
            "timestamp": ts_backup,
            "day": day_num,
            "record_category": "background_service",
            "service_task": "automated_db_backup",
            "Log Source": "SOC Application Logs",
            "Service Name": "adb-backup-scheduler",
            "Host Name": guardian_adb,
            "Event Type": "com.oraclecloud.database.autonomousdatabase.backup",
            "Action": "CreateAutonomousDatabaseBackup",
            "Status": "200",
            "Response Code": "200",
            "DB Target": observeai_adb,
            "DB Statement": "RMAN BACKUP INCREMENTAL LEVEL 1 DATABASE PLUS ARCHIVELOG",
            "Trace ID": bg_trace,
            "Span ID": _deterministic_hex(seed, f"bg-span-db-{day_num}", 16),
            "msg": f"Automated incremental backup completed for {guardian_adb} and {observeai_adb} (Day {day_num})",
        })

        # (b) OKE node kubelet heartbeat (06:20 + offset)
        t_kubelet = dt.datetime.combine(
            current_date, dt.time(6, 18 + (day_idx * 6) % 38, (day_idx * 17) % 60), tzinfo=dt.timezone.utc
        )
        ts_kubelet = _format_iso_utc(t_kubelet)
        background_logs.append({
            "time": ts_kubelet,
            "timestamp": ts_kubelet,
            "Timestamp": ts_kubelet,
            "day": day_num,
            "record_category": "background_service",
            "service_task": "oke_kubelet_heartbeat",
            "Log Source": "SOC Linux Syslog Logs",
            "Hostname": f"{prefix}-oke-worker-0{(day_idx % 2) + 1}",
            "Host Name": f"{prefix}-oke-worker-0{(day_idx % 2) + 1}",
            "Process": "kubelet",
            "Process Name": "kubelet",
            "Command Line": "/usr/bin/kubelet --node-status-update-frequency=10s --cloud-provider=external",
            "Facility": "daemon",
            "Severity": "info",
            "User": "system:node",
            "Source IP": ip_oke_node,
            "Trace ID": bg_trace,
            "msg": f"NodeReady heartbeat status=True kubelet healthz check passed on {prefix}-oke-worker-0{(day_idx % 2) + 1}",
        })

        # (c) CRM-to-Shop order sync job (10:12 + offset)
        t_sync = dt.datetime.combine(
            current_date, dt.time(10, 11 + (day_idx * 5) % 40, (day_idx * 19) % 60), tzinfo=dt.timezone.utc
        )
        ts_sync = _format_iso_utc(t_sync)
        background_logs.append({
            "time": ts_sync,
            "timestamp": ts_sync,
            "day": day_num,
            "record_category": "background_service",
            "service_task": "crm_shop_order_sync",
            "Log Source": "SOC Application Logs",
            "Service Name": "enterprise-crm-portal",
            "Host Name": "crm-portal-sync-worker",
            "HTTP Method": "POST",
            "Request URL": "/api/v1/orders/sync",
            "URI Path": "/api/v1/orders/sync",
            "Response Code": "200",
            "Response Time Ms": 84 + day_idx * 3,
            "Orders Sync Created": 12 + day_idx,
            "Orders Sync Updated": 4 + (day_idx % 3),
            "Orders Sync Failed": 0,
            "Orders Sync Source": "octo-drone-shop",
            "Client IP": ip_crm_sync,
            "Source IP": ip_crm_sync,
            "User": f"svc-order-sync@{corp_mail_domain}",
            "Trace ID": bg_trace,
            "Span ID": _deterministic_hex(seed, f"bg-span-sync-{day_num}", 16),
            "msg": f"Scheduled CRM-to-Shop order synchronization succeeded: created={12 + day_idx} updated={4 + (day_idx % 3)} failed=0",
        })

        # (d) DevOps build pipeline (14:25 + offset)
        t_devops = dt.datetime.combine(
            current_date, dt.time(14, 22 + (day_idx * 7) % 35, (day_idx * 23) % 60), tzinfo=dt.timezone.utc
        )
        ts_devops = _format_iso_utc(t_devops)
        background_logs.append({
            "time": ts_devops,
            "timestamp": ts_devops,
            "day": day_num,
            "record_category": "background_service",
            "service_task": "devops_build_pipeline",
            "Log Source": "OCI Audit Logs",
            "Event Name": "TriggerBuildPipelineRun",
            "Event Type": "com.oraclecloud.devops.buildpipeline.triggerbuildpipelinerun",
            "Principal Name": f"devops-automation@{corp_mail_domain}",
            "User Name": f"devops-automation@{corp_mail_domain}",
            "Client IP": ip_devops,
            "Source IP": ip_devops,
            "Status": "200",
            "Response Code": "200",
            "Resource Name": f"{prefix}-release-pipeline-day{day_num}",
            "Compartment Name": f"{prefix}-applications",
            "Trace ID": bg_trace,
            "msg": f"OCI DevOps build pipeline {prefix}-release-pipeline-day{day_num} completed container verification",
        })

        # (e) IAM token refresh (18:30 + offset)
        t_iam = dt.datetime.combine(
            current_date, dt.time(18, 25 + (day_idx * 5) % 30, (day_idx * 29) % 60), tzinfo=dt.timezone.utc
        )
        ts_iam = _format_iso_utc(t_iam)
        background_logs.append({
            "time": ts_iam,
            "timestamp": ts_iam,
            "day": day_num,
            "record_category": "background_service",
            "service_task": "iam_token_refresh",
            "Log Source": "OCI Audit Logs",
            "Event Name": "GenerateScopedAccessToken",
            "Event Type": "com.oraclecloud.identitydataplane.generatescopedaccesstoken",
            "Principal Name": f"oke-workload-identity-sa@{corp_mail_domain}",
            "User Name": f"oke-workload-identity-sa@{corp_mail_domain}",
            "Client IP": ip_iam_sa,
            "Source IP": ip_iam_sa,
            "Status": "200",
            "Response Code": "200",
            "Resource Name": "observeai-workload-token",
            "Compartment Name": f"{prefix}-observability",
            "Trace ID": bg_trace,
            "msg": "Scheduled OKE workload identity UPST token refresh completed normally",
        })
