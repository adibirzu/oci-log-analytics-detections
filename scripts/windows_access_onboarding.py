#!/usr/bin/env python3
"""Plan and validate the OCI Log Analytics Windows access-monitoring fast track.

The default commands are tenant-neutral and do not call OCI. Continuous
collection deliberately reuses Oracle-defined Windows Event sources; creating
custom Microsoft Windows sources would duplicate parsers and field mappings.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


NATIVE_SOURCES = [
    {
        "display_name": "Windows Security Events",
        "internal_name": "MsftWinEventSecurityLogSource",
        "channel": "Security",
    },
    {
        "display_name": "Windows System Events",
        "internal_name": "MsftWinEventSystemLogSource",
        "channel": "System",
    },
    {
        "display_name": "Windows Application Events",
        "internal_name": "MsftWinEventApplicationLogSource",
        "channel": "Application",
    },
]

REQUIRED_FIELDS = [
    "Time",
    "Event ID",
    "Logon Type",
    "Source Address",
    "Subject User Name",
    "Target User Name",
    "Host Name (Server)",
    "User",
    "Message",
]

EVENT_IDS = ["4624", "4625", "4634", "4648", "4672", "4720", "4726", "4732", "4733", "4776"]

ALERT_SEARCHES = [
    {
        "id": "failed-logon-burst",
        "title": "Windows Failed Logon Burst by Source",
        "query_file": "queries/hunting/windows_access_failed_logon_burst.json",
        "schedule": "5m",
        "condition": "FailedLogons > 10",
    },
    {
        "id": "rdp-after-hours",
        "title": "Windows Successful RDP Logon Outside Business Hours",
        "query_file": "queries/hunting/windows_access_rdp_after_hours.json",
        "schedule": "5m",
        "condition": "RDPLogons > 0",
    },
    {
        "id": "administrator-logon",
        "title": "Windows Administrator Logon",
        "query_file": "queries/hunting/windows_access_administrator_logon.json",
        "schedule": "5m",
        "condition": "AdministratorLogons > 0",
    },
    {
        "id": "new-local-user",
        "title": "Windows New Local User Created",
        "query_file": "queries/hunting/windows_access_new_local_user.json",
        "schedule": "5m",
        "condition": "UsersCreated > 0",
    },
    {
        "id": "privileged-local-group-add",
        "title": "Windows User Added to Administrators or Remote Desktop Users",
        "query_file": "queries/hunting/windows_access_privileged_group_add.json",
        "schedule": "5m",
        "condition": "GroupAdds > 0",
    },
]

PROJECT_DIR = Path(__file__).resolve().parents[1]
METRIC_NAMESPACE = "logan_windows_access"


def build_association_template(
    *,
    agent_id: str,
    entity_id: str,
    log_group_id: str,
) -> dict[str, Any]:
    """Build the reviewable body for ``upsert-assocs`` without calling OCI."""
    return {
        "schema_version": "1.0.0",
        "evidence_class": "code-backed",
        "applied": False,
        "operation": "oci log-analytics assoc upsert-assocs",
        "items": [
            {
                "agentId": agent_id,
                "entityId": entity_id,
                "logGroupId": log_group_id,
                "sourceName": source["internal_name"],
            }
            for source in NATIVE_SOURCES
        ],
        "review_before_apply": [
            "Resolve the exact profile, region, namespace, compartment, agent, entity, and log group.",
            "Confirm each Oracle-defined source exists before association.",
            "Association starts continuous collection and is a live tenancy mutation.",
        ],
    }


def _placeholder_name(alert_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", alert_id).strip("_").upper()


def _dimension_name(field_name: str) -> str:
    """Return a Monitoring-safe dimension label without field punctuation."""
    words = re.findall(r"[A-Za-z0-9]+", field_name)
    return "".join(word[:1].upper() + word[1:] for word in words)


def build_alert_plan(
    *,
    log_analytics_compartment_id: str,
    metric_compartment_id: str,
    alarm_compartment_id: str,
    notification_topic_id: str,
) -> dict[str, Any]:
    """Build scheduled-task and disabled-alarm payloads without calling OCI.

    Each scheduled task still requires the OCID of a saved search created from
    the referenced query. The returned alarms are deliberately disabled until
    a canary run proves that the scheduled task emits the expected metric.
    """
    from detection_rule_creator import build_detection_rule_spec

    scheduled_tasks: list[dict[str, Any]] = []
    alarms: list[dict[str, Any]] = []
    for alert in ALERT_SEARCHES:
        query_path = PROJECT_DIR / alert["query_file"]
        payload = json.loads(query_path.read_text())
        spec = build_detection_rule_spec(alert["query_file"], payload)
        if not spec["eligible"]:
            raise ValueError(f"Scheduled-search-ineligible query {alert['query_file']}: {spec['reasons']}")

        metric_name = spec["metric_name"]
        dimensions = [
            {"queryFieldName": field, "dimensionName": _dimension_name(field)}
            for field in spec["dimensions"]
        ]
        saved_search_id = f"<{_placeholder_name(alert['id'])}_SAVED_SEARCH_OCID>"
        scheduled_tasks.append(
            {
                "id": alert["id"],
                "displayName": f"Windows Access - {alert['title']}",
                "compartmentId": log_analytics_compartment_id,
                "taskType": "SAVED_SEARCH",
                "action": {
                    "type": "STREAM",
                    "savedSearchId": saved_search_id,
                    "savedSearchDuration": "PT5M",
                    "metricExtraction": {
                        "compartmentId": metric_compartment_id,
                        "namespace": METRIC_NAMESPACE,
                        "resourceGroup": "windows_access",
                        "metricName": metric_name,
                        "metricCollections": [
                            {
                                "metricName": metric_name,
                                "metricQueryFieldName": metric_name,
                                "dimensions": dimensions,
                            }
                        ],
                    },
                },
                "schedules": [
                    {
                        "type": "FIXED_FREQUENCY",
                        "misfirePolicy": "RETRY_ONCE",
                        "recurringInterval": "PT5M",
                        "repeatCount": -1,
                    }
                ],
                "dimensions": spec["dimensions"],
                "queryFile": alert["query_file"],
            }
        )
        alarms.append(
            {
                "id": alert["id"],
                "displayName": f"Windows Access - {alert['title']}",
                "compartmentId": alarm_compartment_id,
                "metricCompartmentId": metric_compartment_id,
                "namespace": METRIC_NAMESPACE,
                "resourceGroup": "windows_access",
                "query": f"{metric_name}[5m].sum() > 0",
                "severity": str(spec["severity"]).upper(),
                "destinations": [notification_topic_id],
                "isEnabled": False,
                "pendingDuration": "PT1M",
            }
        )

    return {
        "schema_version": "1.0.0",
        "evidence_class": "code-backed",
        "applied": False,
        "metric_namespace": METRIC_NAMESPACE,
        "scheduled_tasks": scheduled_tasks,
        "alarms": alarms,
        "apply_order": [
            "Create and live-validate each saved search.",
            "Replace every saved-search placeholder, then create scheduled tasks.",
            "Prove each scheduled task emits a numeric metric with expected dimensions.",
            "Create alarms disabled, validate notification ownership, then enable canaries one at a time.",
        ],
    }


def render_cli_bundle(
    *,
    output_dir: Path,
    namespace_name: str,
    log_analytics_compartment_id: str,
    metric_compartment_id: str,
    alarm_compartment_id: str,
    notification_topic_id: str,
    agent_id: str,
    entity_id: str,
    log_group_id: str,
    force: bool = False,
) -> dict[str, Any]:
    """Write one reviewable OCI CLI JSON file per mutation.

    Rendering is offline. Saved-search placeholders intentionally prevent a
    scheduled task from being usable until the dashboard's embedded saved
    searches have been created, listed, and mapped by exact display name.
    """
    output_dir = Path(output_dir)
    association = build_association_template(
        agent_id=agent_id,
        entity_id=entity_id,
        log_group_id=log_group_id,
    )
    alerts = build_alert_plan(
        log_analytics_compartment_id=log_analytics_compartment_id,
        metric_compartment_id=metric_compartment_id,
        alarm_compartment_id=alarm_compartment_id,
        notification_topic_id=notification_topic_id,
    )

    files: dict[str, Any] = {
        "association.json": {
            "namespaceName": namespace_name,
            "compartmentId": log_analytics_compartment_id,
            "items": association["items"],
        }
    }
    for task in alerts["scheduled_tasks"]:
        files[f"scheduled-task-{task['id']}.json"] = {
            "namespaceName": namespace_name,
            "compartmentId": task["compartmentId"],
            "displayName": task["displayName"],
            "taskType": task["taskType"],
            "action": task["action"],
            "schedules": task["schedules"],
        }
    for alarm in alerts["alarms"]:
        files[f"alarm-{alarm['id']}.json"] = {
            key: value for key, value in alarm.items() if key != "id"
        }

    manifest = {
        "schema_version": "1.0.0",
        "evidence_class": "code-backed",
        "applied": False,
        "blocking_gates": [
            "confirm_exact_target",
            "replace_saved_search_placeholders",
            "review_iam_and_notification_ownership",
            "obtain_explicit_mutation_approval",
        ],
        "apply_sequence": [
            {
                "file": "association.json",
                "command": "oci log-analytics assoc upsert-assocs --from-json file://association.json",
                "verify": "Re-list the exact entity's source associations and prove new rows.",
            },
            {
                "files": "scheduled-task-*.json",
                "command": "oci log-analytics scheduled-task create-standard-task --from-json file://<FILE>",
                "verify": "Confirm ACTIVE/READY and numeric metric emission in Monitoring.",
            },
            {
                "files": "alarm-*.json",
                "command": "oci monitoring alarm create --from-json file://<FILE>",
                "verify": "Confirm alarms exist disabled; enable canaries separately after notification review.",
            },
        ],
        "files": sorted([*files, "manifest.json"]),
    }
    files["manifest.json"] = manifest

    output_dir.mkdir(parents=True, exist_ok=True)
    collisions = [name for name in files if (output_dir / name).exists()]
    if collisions and not force:
        raise FileExistsError(
            f"Refusing to overwrite existing bundle files: {', '.join(sorted(collisions))}. Use --force after review."
        )
    for filename, payload in files.items():
        (output_dir / filename).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    return {
        "schema_version": "1.0.0",
        "evidence_class": "code-backed",
        "applied": False,
        "output_dir": str(output_dir),
        "file_count": len(files),
        "files": sorted(files),
    }


def build_plan() -> dict[str, Any]:
    """Return the portable onboarding contract without accessing OCI."""
    return {
        "schema_version": "1.0.0",
        "evidence_class": "code-backed",
        "continuous_collection": {
            "transport": "Oracle Management Agent with Log Analytics plugin",
            "source_action": "validate_and_associate_oracle_defined_sources",
            "sources": NATIVE_SOURCES,
        },
        "required_fields": REQUIRED_FIELDS,
        "event_ids": EVENT_IDS,
        "alert_searches": ALERT_SEARCHES,
        "dashboard": "SOC: Windows Access Monitoring",
        "live_apply_requires": [
            "Windows host or OCI instance OCID",
            "OCI CLI profile",
            "region",
            "compartment OCID",
            "Log Analytics namespace",
            "Windows entity OCID",
            "explicit approval for source association and dashboard/search creation",
        ],
    }


def _event_value(record: dict[str, Any], *field_names: str) -> str:
    for field_name in field_names:
        value = record.get(field_name)
        if value not in (None, ""):
            return str(value)
    return ""


def evaluate_access_alerts(
    records: list[dict[str, Any]],
    *,
    business_start_hour: int = 8,
    business_end_hour: int = 18,
) -> dict[str, Any]:
    """Evaluate the five pack semantics against normalized Windows events.

    This local evaluator is intentionally independent of OCI. It proves that
    generated fixtures exercise each contract before any tenancy mutation.
    """
    evidence: dict[str, list[dict[str, Any]]] = {item["id"]: [] for item in ALERT_SEARCHES}
    failures_by_source: dict[str, list[datetime]] = defaultdict(list)

    for record in records:
        event_id = _event_value(record, "Event ID", "EventID")
        target_user = _event_value(record, "Target User Name", "TargetUserName", "User")
        source_address = _event_value(record, "Source Address", "SourceAddress", "IpAddress")
        host = _event_value(record, "Host Name (Server)", "Computer", "Entity")
        timestamp_text = _event_value(record, "TimeCreated", "Time")
        timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))

        if event_id == "4625" and source_address:
            failures_by_source[source_address].append(timestamp)
        if event_id == "4624" and _event_value(record, "Logon Type", "LogonType") == "10":
            if timestamp.hour < business_start_hour or timestamp.hour >= business_end_hour:
                evidence["rdp-after-hours"].append(
                    {"user": target_user, "source_address": source_address, "host": host, "time": timestamp_text}
                )
        if event_id == "4624" and target_user.lower().endswith("administrator"):
            evidence["administrator-logon"].append(
                {"user": target_user, "source_address": source_address, "host": host, "time": timestamp_text}
            )
        if event_id == "4720":
            evidence["new-local-user"].append({"user": target_user, "host": host, "time": timestamp_text})
        if event_id == "4732" and target_user.lower() in {"administrators", "remote desktop users"}:
            evidence["privileged-local-group-add"].append(
                {
                    "group": target_user,
                    "member": _event_value(record, "Member Name", "MemberName"),
                    "host": host,
                    "time": timestamp_text,
                }
            )

    for source_address, timestamps in failures_by_source.items():
        ordered = sorted(timestamps)
        for start_index, start in enumerate(ordered):
            count = sum(1 for value in ordered[start_index:] if (value - start).total_seconds() <= 300)
            if count > 10:
                evidence["failed-logon-burst"].append(
                    {"source_address": source_address, "count": count, "window_start": start.isoformat()}
                )
                break

    triggered = [item["id"] for item in ALERT_SEARCHES if evidence[item["id"]]]
    return {
        "status": "passed" if len(triggered) == len(ALERT_SEARCHES) else "failed",
        "evidence_class": "locally verified",
        "triggered_alerts": triggered,
        "evidence": evidence,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan", help="Print the tenant-neutral onboarding plan")
    plan_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    local_parser = subparsers.add_parser("validate-local", help="Run deterministic local E2E alert validation")
    local_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    local_parser.add_argument("--business-start-hour", type=int, default=8)
    local_parser.add_argument("--business-end-hour", type=int, default=18)
    association_parser = subparsers.add_parser(
        "association-template",
        help="Print a review-only native Windows source-association body",
    )
    association_parser.add_argument("--agent-id", default="<MANAGEMENT_AGENT_OCID>")
    association_parser.add_argument("--entity-id", default="<WINDOWS_ENTITY_OCID>")
    association_parser.add_argument("--log-group-id", default="<LOG_GROUP_OCID>")
    alert_parser = subparsers.add_parser(
        "alert-plan",
        help="Print review-only scheduled-task and disabled-alarm payloads",
    )
    alert_parser.add_argument("--log-analytics-compartment-id", default="<LA_COMPARTMENT_OCID>")
    alert_parser.add_argument("--metric-compartment-id", default="<METRIC_COMPARTMENT_OCID>")
    alert_parser.add_argument("--alarm-compartment-id", default="<ALARM_COMPARTMENT_OCID>")
    alert_parser.add_argument("--notification-topic-id", default="<NOTIFICATION_TOPIC_OCID>")
    bundle_parser = subparsers.add_parser(
        "render-cli-bundle",
        help="Write one reviewable OCI CLI JSON file per association, scheduled task, and disabled alarm",
    )
    bundle_parser.add_argument("--output-dir", required=True, type=Path)
    bundle_parser.add_argument("--namespace-name", default="<LA_NAMESPACE>")
    bundle_parser.add_argument("--log-analytics-compartment-id", default="<LA_COMPARTMENT_OCID>")
    bundle_parser.add_argument("--metric-compartment-id", default="<METRIC_COMPARTMENT_OCID>")
    bundle_parser.add_argument("--alarm-compartment-id", default="<ALARM_COMPARTMENT_OCID>")
    bundle_parser.add_argument("--notification-topic-id", default="<NOTIFICATION_TOPIC_OCID>")
    bundle_parser.add_argument("--agent-id", default="<MANAGEMENT_AGENT_OCID>")
    bundle_parser.add_argument("--entity-id", default="<WINDOWS_ENTITY_OCID>")
    bundle_parser.add_argument("--log-group-id", default="<LOG_GROUP_OCID>")
    bundle_parser.add_argument("--force", action="store_true", help="Overwrite existing bundle files after review")
    args = parser.parse_args()

    if args.command == "plan":
        plan = build_plan()
        if args.json:
            print(json.dumps(plan, indent=2, sort_keys=True))
        else:
            print("Windows Access Monitoring fast track")
            print(json.dumps(plan, indent=2, sort_keys=True))
        return 0
    if args.command == "validate-local":
        from windows_eventlog_synthetic import generate_all

        report = evaluate_access_alerts(
            generate_all()["windows_event_security.jsonl"],
            business_start_hour=args.business_start_hour,
            business_end_hour=args.business_end_hour,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["status"] == "passed" else 1
    if args.command == "association-template":
        print(
            json.dumps(
                build_association_template(
                    agent_id=args.agent_id,
                    entity_id=args.entity_id,
                    log_group_id=args.log_group_id,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "alert-plan":
        print(
            json.dumps(
                build_alert_plan(
                    log_analytics_compartment_id=args.log_analytics_compartment_id,
                    metric_compartment_id=args.metric_compartment_id,
                    alarm_compartment_id=args.alarm_compartment_id,
                    notification_topic_id=args.notification_topic_id,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "render-cli-bundle":
        print(
            json.dumps(
                render_cli_bundle(
                    output_dir=args.output_dir,
                    namespace_name=args.namespace_name,
                    log_analytics_compartment_id=args.log_analytics_compartment_id,
                    metric_compartment_id=args.metric_compartment_id,
                    alarm_compartment_id=args.alarm_compartment_id,
                    notification_topic_id=args.notification_topic_id,
                    agent_id=args.agent_id,
                    entity_id=args.entity_id,
                    log_group_id=args.log_group_id,
                    force=args.force,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
