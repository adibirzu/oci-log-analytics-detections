#!/usr/bin/env python3
"""Offline operator CLI and deterministic local E2E harness.

No command in this module imports the OCI SDK, opens a socket, or mutates a
provider.  The local harness replaces only the production service's ports.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping, Sequence

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.splunk_evidence_exporter.models import AlarmTrigger, ExportBatch
from scripts.splunk_evidence_exporter.retry import classify_hec_failure
from scripts.splunk_evidence_exporter.service import EvidenceExportService
from scripts.splunk_delivery_contracts import registry_validation_errors


FIXTURES = ROOT / "scripts/fixtures/splunk_evidence"
REGISTRY_PATH = ROOT / "queries/splunk_detection_registry.json"
CONFIG_PATH = ROOT / "config/splunk_parallel_delivery.yaml"


def _offline(document: Mapping[str, object]) -> dict[str, object]:
    return {"offline": True, "external_calls": [], **document}


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_hashes() -> dict[str, str]:
    return {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(FIXTURES.glob("*.json"))
    }


class _Registry:
    def __init__(self, document: Mapping[str, object]) -> None:
        self._document = document

    def load(self) -> Mapping[str, object]:
        return self._document


class _FixtureQueryAdapter:
    def __init__(
        self, rows: Sequence[Mapping[str, object]], operations: list[str]
    ) -> None:
        self._rows = tuple(rows)
        self._operations = operations

    def query_evidence(self, **request: object) -> tuple[Mapping[str, object], ...]:
        self._operations.append("query_executed")
        maximum = request["max_rows"]
        if not isinstance(maximum, int):
            raise RuntimeError("local query row bound is invalid")
        return self._rows[:maximum]


class _InMemoryCheckpointAdapter:
    def __init__(self, operations: list[str]) -> None:
        self._operations = operations
        self._value: datetime | None = None
        self.committed = False

    def load_checkpoint(
        self, detection_id: str, dimensions: Mapping[str, str]
    ) -> datetime | None:
        self._operations.append("checkpoint_loaded")
        return self._value

    def save_checkpoint(
        self,
        detection_id: str,
        dimensions: Mapping[str, str],
        checkpoint: datetime,
    ) -> None:
        self._value = checkpoint
        self.committed = True
        self._operations.append("checkpoint_committed")


class _InProcessHecAdapter:
    def __init__(
        self,
        responses: Sequence[Mapping[str, object] | str],
        operations: list[str],
        *,
        max_attempts: int = 1,
    ) -> None:
        self._responses = tuple(responses)
        self._operations = operations
        self.events: list[Mapping[str, object]] = []
        self.attempts = 0
        self._max_attempts = max_attempts

    def deliver(self, batch: ExportBatch) -> Mapping[str, object]:
        last_response: Mapping[str, object] | None = None
        for attempt in range(self._max_attempts):
            self.attempts += 1
            self._operations.append("mock_hec_attempted")
            response = self._responses[min(attempt, len(self._responses) - 1)]
            if response == "missing-secret":
                raise RuntimeError(
                    "sensitive-marker-never-print raw-provider-identifier-never-print"
                )
            if response == "timeout":
                raise TimeoutError(
                    "sensitive-marker-never-print raw-provider-identifier-never-print"
                )
            last_response = response
            outcome = classify_hec_failure(
                response.get("status"), response=response.get("response")
            )
            if outcome == "success":
                self.events.extend(event.to_dict() for event in batch.events)
                self._operations.append("mock_hec_delivered")
                return response
            if outcome != "retryable":
                return response
        if last_response is None:
            raise RuntimeError("local HEC response fixture is empty")
        return last_response


class _InMemoryDeadLetterAdapter:
    def __init__(self, operations: list[str], *, fail_write: bool = False) -> None:
        self.records: list[dict[str, object]] = []
        self._operations = operations
        self._fail_write = fail_write

    def quarantine(
        self,
        batch: ExportBatch,
        reason: str,
        *,
        delivered_event_keys: Sequence[str] = (),
    ) -> None:
        if self._fail_write:
            self._operations.append("dlq_write_failed")
            raise RuntimeError(
                "sensitive-marker-never-print raw-provider-identifier-never-print"
            )
        self.records.append(
            {
                "reason": reason,
                "event_count": len(batch.events),
                "delivered_event_key_count": len(delivered_event_keys),
                "event_keys": tuple(event.event_key for event in batch.events),
            }
        )
        self._operations.append("dlq_written")


def _plan() -> dict[str, object]:
    registry = _read_json(REGISTRY_PATH)
    if not isinstance(registry, Mapping) or not isinstance(
        registry.get("detections"), list
    ):
        raise RuntimeError("detection registry is invalid")
    detections = registry["detections"]
    return _offline(
        {
            "schema_version": "oci.logan.splunk.offline-plan.v1",
            "modes": [
                {
                    "id": "raw",
                    "enabled_by_default": False,
                    "flow": "OCI Logging -> Service Connector Hub -> Streaming -> Splunk HEC",
                },
                {
                    "id": "evidence",
                    "enabled_by_default": False,
                    "flow": "Monitoring -> Notifications -> Function -> Log Analytics -> Splunk HEC",
                },
            ],
            "detection_count": len(detections),
            "detections": [entry["id"] for entry in detections],
            "components": [
                "OCI Logging",
                "Service Connector Hub",
                "OCI Streaming",
                "OCI Log Analytics",
                "OCI Monitoring",
                "OCI Notifications",
                "OCI Functions",
                "OCI Vault",
                "Object Storage checkpoint and DLQ",
                "Splunk HEC",
            ],
            "policy_categories": [
                "log-read",
                "log-analytics-query",
                "notifications-function-invoke",
                "vault-secret-read",
                "checkpoint-dlq-object-access",
                "operational-telemetry",
            ],
            "evidence_gates": [
                "code_backed",
                "configured",
                "locally_verified",
                "provider_verified",
                "release_accepted",
            ],
        }
    )


def _validate_config() -> dict[str, object]:
    try:
        config = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        raise RuntimeError("delivery configuration is unavailable or invalid") from None
    registry = _read_json(REGISTRY_PATH)
    if not isinstance(config, Mapping) or not isinstance(registry, Mapping):
        raise RuntimeError("delivery configuration is invalid")
    configured = config.get("detections")
    registry_entries = registry.get("detections")
    if not isinstance(configured, Mapping) or not isinstance(
        configured.get("migrations"), list
    ):
        raise RuntimeError("delivery detection configuration is invalid")
    if not isinstance(registry_entries, list):
        raise RuntimeError("detection registry is invalid")
    errors: list[str] = []
    for entry in registry_entries:
        if not isinstance(entry, dict):
            errors.append("registry entry must be an object")
            continue
        errors.extend(registry_validation_errors(entry, ROOT))
    configured_ids = {
        entry.get("id")
        for entry in configured["migrations"]
        if isinstance(entry, Mapping)
    }
    registry_ids = {
        entry.get("id") for entry in registry_entries if isinstance(entry, Mapping)
    }
    if configured_ids != registry_ids:
        errors.append("delivery configuration and registry IDs differ")
    if errors:
        raise RuntimeError("delivery configuration validation failed")
    return _offline(
        {
            "schema_version": "oci.logan.splunk.config-validation.v1",
            "status": "valid",
            "detection_count": len(registry_entries),
            "canonical_query_count": len(registry_entries),
            "credentials_present": False,
            "evidence_class": "locally_verified",
        }
    )


def _validate_payload(path: Path) -> dict[str, object]:
    document = _read_json(path)
    if not isinstance(document, Mapping):
        raise ValueError("alarm payload must be one object")
    trigger = AlarmTrigger.from_payload(document)
    registry = _read_json(REGISTRY_PATH)
    detections = registry.get("detections") if isinstance(registry, Mapping) else None
    if not isinstance(detections, list):
        raise RuntimeError("detection registry is invalid")
    known_ids = {entry.get("id") for entry in detections if isinstance(entry, Mapping)}
    if trigger.detection_id not in known_ids:
        raise ValueError("alarm detection is not present in the registry")
    return _offline(
        {
            "schema_version": "oci.logan.splunk.payload-validation.v1",
            "status": "valid",
            "payload_kind": "monitoring-alarm",
            "detection_id": trigger.detection_id,
            "dimension_count": len(trigger.dimensions),
            "contains_credentials": False,
            "evidence_class": "locally_verified",
        }
    )


def _render_function_config() -> dict[str, object]:
    return _offline(
        {
            "schema_version": "oci.logan.splunk.function-config-template.v1",
            "enabled": False,
            "requires_target_review": True,
            "environment": {
                "OBJECT_STORAGE_NAMESPACE": "<OBJECT_STORAGE_NAMESPACE>",
                "SPLUNK_EVIDENCE_STATE_BUCKET": "<STATE_BUCKET_NAME>",
                "SPLUNK_EVIDENCE_DLQ_BUCKET": "<DLQ_BUCKET_NAME>",
                "OCI_LOG_ANALYTICS_COMPARTMENT_ID": "<LOG_ANALYTICS_COMPARTMENT_ID>",
                "OCI_LOG_ANALYTICS_COMPARTMENT_IN_SUBTREE": "false",
                "SPLUNK_HEC_SECRET_ID": "<EXISTING_VAULT_SECRET_ID>",
                "SPLUNK_HEC_URL": "https://<SPLUNK_HEC_HOST>/services/collector/event",
                "SPLUNK_HEC_INDEX": "<SPLUNK_INDEX>",
                "SPLUNK_HEC_SOURCETYPE": "oci:logan:detection",
                "SPLUNK_HEC_ACKNOWLEDGEMENT_MODE": "response",
                "SPLUNK_HEC_TIMEOUT_SECONDS": "10",
                "SPLUNK_EVIDENCE_MAX_ROWS": "1000",
                "SPLUNK_HEC_MAX_BATCH_EVENTS": "100",
            },
            "secret_handling": "Vault reference only; the HEC token is never rendered",
        }
    )


def _render_iam() -> dict[str, object]:
    categories = [
        {
            "id": "log-analytics-query",
            "principal": "<FUNCTION_DYNAMIC_GROUP_NAME>",
            "scope": "<LOG_ANALYTICS_COMPARTMENT_NAME>",
            "permissions": [
                "LOG_ANALYTICS_QUERY_VIEW",
                "LOG_ANALYTICS_QUERYJOB_WORK_REQUEST_READ",
                "read loganalytics-log-group",
            ],
        },
        {
            "id": "vault-secret-read",
            "principal": "<FUNCTION_DYNAMIC_GROUP_NAME>",
            "scope": "<VAULT_COMPARTMENT_NAME>",
            "resource": "<EXISTING_VAULT_SECRET_ID>",
        },
        {
            "id": "checkpoint-dlq-object-access",
            "principal": "<FUNCTION_DYNAMIC_GROUP_NAME>",
            "scope": "<STATE_COMPARTMENT_NAME>",
            "resources": ["<STATE_BUCKET_NAME>", "<DLQ_BUCKET_NAME>"],
        },
        {
            "id": "notifications-function-invoke",
            "principal": "OCI Notifications",
            "scope": "<FUNCTION_COMPARTMENT_NAME>",
            "resource": "<FUNCTION_NAME>",
        },
        {
            "id": "operational-telemetry",
            "principal": "<FUNCTION_DYNAMIC_GROUP_NAME>",
            "scope": "<FUNCTION_COMPARTMENT_NAME>",
        },
    ]
    return _offline(
        {
            "schema_version": "oci.logan.splunk.iam-review.v1",
            "requires_scope_review": True,
            "apply_supported": False,
            "policy_categories": categories,
            "review_gate": (
                "Resolve every placeholder and verify current Oracle IAM policy syntax "
                "before any separately approved apply"
            ),
        }
    )


def _canary_plan() -> dict[str, object]:
    return _offline(
        {
            "schema_version": "oci.logan.splunk.canary-plan.v1",
            "executes": False,
            "approval_required": True,
            "steps": [
                "Record target, authorization boundary, owner, window, and stop conditions",
                "Resolve profile, region, compartments, Log Analytics namespace, and one detection",
                "Review Function, Notifications, Vault reference, state, DLQ, network, TLS, and IAM scope",
                "Confirm alarm and subscription remain disabled before the change window",
                "Generate or identify one approved canary event",
                "Verify the event and derived evidence in OCI Log Analytics",
                "Enable only the reviewed canary path under separate live approval",
                "Verify HEC acknowledgement, Splunk searchability, and checkpoint commit",
                "Disable or promote the canary and record rollback, cost, replay, and retention acceptance",
            ],
            "required_evidence": [
                "authenticated target receipt",
                "Log Analytics query result",
                "HEC acknowledgement",
                "Splunk search result",
                "checkpoint receipt",
                "rollback or promotion decision",
            ],
        }
    )


def _replay_plan() -> dict[str, object]:
    return _offline(
        {
            "schema_version": "oci.logan.splunk.replay-plan.v1",
            "executes": False,
            "approval_required": True,
            "steps": [
                "Record replay approver, target, batch, time window, and stop conditions",
                "Inspect the sanitized DLQ manifest and previously delivered event keys",
                "Confirm HEC credential, endpoint, index, sourcetype, TLS, and capacity",
                "Bound the replay to remaining events and preserve their event keys",
                "Deliver through the reviewed exporter path and require HEC acknowledgement",
                "Commit the checkpoint only after every remaining batch is confirmed",
                "Retain a replay receipt and quarantine failures without silent loss",
            ],
            "safety": {
                "duplicate_tolerance": "stable event_key",
                "checkpoint_rule": "commit only after confirmed delivery",
                "dlq_rule": "preserve until replay receipt is accepted",
            },
        }
    )


def _service(
    query: _FixtureQueryAdapter,
    checkpoint: _InMemoryCheckpointAdapter,
    hec: _InProcessHecAdapter,
    dead_letter: _InMemoryDeadLetterAdapter,
) -> EvidenceExportService:
    registry = _read_json(REGISTRY_PATH)
    if not isinstance(registry, Mapping):
        raise RuntimeError("detection registry is invalid")
    return EvidenceExportService(
        registry=_Registry(registry),
        query=query,
        checkpoint=checkpoint,
        hec=hec,
        dead_letter=dead_letter,
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2),
        maximum_window=timedelta(hours=2),
        max_rows=1000,
        max_batch_events=100,
    )


def _local_e2e(scenario: str, *, approve_replay: bool = False) -> dict[str, object]:
    supported = {
        "success",
        "duplicate-invocation",
        "zero-evidence",
        "timeout",
        "429",
        "500",
        "400",
        "401",
        "oversized-batch",
        "missing-secret",
        "dlq-write",
        "dlq-failure",
        "retry-exhaustion",
        "approved-replay",
    }
    if scenario not in supported:
        raise ValueError("unsupported local E2E scenario")
    if scenario == "approved-replay" and not approve_replay:
        raise ValueError("replay requires explicit approval")
    alarm = _read_json(FIXTURES / "alarm.json")
    rows = _read_json(FIXTURES / "query_rows.json")
    responses = _read_json(FIXTURES / "hec_responses.json")
    if (
        not isinstance(alarm, Mapping)
        or not isinstance(rows, list)
        or not isinstance(responses, Mapping)
    ):
        raise RuntimeError("local E2E fixtures are invalid")
    operations: list[str] = []
    scenario_rows = [] if scenario == "zero-evidence" else rows
    query = _FixtureQueryAdapter(scenario_rows, operations)
    checkpoint = _InMemoryCheckpointAdapter(operations)
    response_name = {
        "success": "success",
        "duplicate-invocation": "success",
        "zero-evidence": "success",
        "dlq-write": "500",
        "dlq-failure": "500",
        "retry-exhaustion": "500",
        "missing-secret": "missing-secret",
        "approved-replay": "500",
    }.get(scenario, scenario)
    response_sequence = (
        ["missing-secret"]
        if response_name == "missing-secret"
        else responses[response_name]
    )
    hec = _InProcessHecAdapter(
        response_sequence,
        operations,
        max_attempts=4 if scenario == "retry-exhaustion" else 1,
    )
    dead_letter = _InMemoryDeadLetterAdapter(
        operations, fail_write=scenario == "dlq-failure"
    )
    service = _service(query, checkpoint, hec, dead_letter)
    trigger = AlarmTrigger.from_payload(alarm)
    receipt = service.export(trigger)
    initial_status: str | None = None
    replayed_event_count = 0
    replay_approved = False
    replay_matches_quarantined_events = False
    total_hec_attempts = hec.attempts
    if scenario == "approved-replay":
        initial_status = receipt.status
        replay_hec = _InProcessHecAdapter(responses["success"], operations)
        receipt = _service(query, checkpoint, replay_hec, dead_letter).export(trigger)
        hec = replay_hec
        replayed_event_count = len(replay_hec.events)
        replay_approved = True
        replay_matches_quarantined_events = (
            tuple(event["event_key"] for event in replay_hec.events)
            == dead_letter.records[0]["event_keys"]
        )
        total_hec_attempts += replay_hec.attempts
    invocation_count = 1
    first_event_keys = [event["event_key"] for event in hec.events]
    if scenario == "duplicate-invocation":
        receipt = service.export(trigger)
        invocation_count = 2
        total_hec_attempts = hec.attempts
    all_event_keys = [event["event_key"] for event in hec.events]
    unique_event_keys = set(all_event_keys)
    return {
        "scenario": scenario,
        "service": "EvidenceExportService",
        **receipt.to_dict(),
        "query_row_count": receipt.row_count,
        "mock_hec_event_count": len(hec.events),
        "hec_attempt_count": total_hec_attempts,
        "dlq_record_count": len(dead_letter.records),
        "dlq_reason": (
            dead_letter.records[0]["reason"] if dead_letter.records else None
        ),
        "operations": operations,
        "evidence_class": "locally_verified",
        "provider_validation": "not_run",
        "provider_verified": False,
        "invocation_count": invocation_count,
        "stable_event_keys": (
            invocation_count == 2
            and first_event_keys == all_event_keys[len(first_event_keys) :]
        ),
        "duplicate_event_count": len(all_event_keys) - len(unique_event_keys),
        "initial_status": initial_status,
        "replay_approved": replay_approved,
        "replayed_event_count": replayed_event_count,
        "replay_matches_quarantined_events": replay_matches_quarantined_events,
        "scenario_counts": {
            "query_rows": receipt.row_count,
            "events": receipt.event_count,
            "batches": receipt.batch_count,
            "delivered": receipt.delivered_count,
            "hec_attempts": total_hec_attempts,
            "dlq_records": len(dead_letter.records),
            "invocations": invocation_count,
            "duplicates": len(all_event_keys) - len(unique_event_keys),
            "replayed": replayed_event_count,
        },
        "artifact_hashes": _fixture_hashes(),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan", help="render the offline delivery plan")
    plan.add_argument("--json", action="store_true")
    local = subparsers.add_parser("local-e2e", help="run an in-process E2E scenario")
    local.add_argument("--scenario", default="success")
    local.add_argument("--approve-replay", action="store_true")
    subparsers.add_parser("validate-config", help="validate local delivery artifacts")
    payload = subparsers.add_parser(
        "validate-payload", help="validate one sanitized alarm payload"
    )
    payload.add_argument("path", nargs="?", type=Path)
    payload.add_argument("--file", dest="file_path", type=Path)
    subparsers.add_parser(
        "render-function-config", help="render a disabled Function configuration"
    )
    subparsers.add_parser("render-iam", help="render IAM review categories")
    subparsers.add_parser("canary-plan", help="render a non-executing canary plan")
    subparsers.add_parser("replay-plan", help="render a non-executing replay plan")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "plan":
            output = _plan()
        elif arguments.command == "local-e2e":
            output = _local_e2e(
                arguments.scenario, approve_replay=arguments.approve_replay
            )
        elif arguments.command == "validate-config":
            output = _validate_config()
        elif arguments.command == "validate-payload":
            path = arguments.file_path or arguments.path or FIXTURES / "alarm.json"
            output = _validate_payload(path)
        elif arguments.command == "render-function-config":
            output = _render_function_config()
        elif arguments.command == "render-iam":
            output = _render_iam()
        elif arguments.command == "canary-plan":
            output = _canary_plan()
        elif arguments.command == "replay-plan":
            output = _replay_plan()
        else:
            raise RuntimeError("unsupported command")
    except Exception as exc:
        print(
            json.dumps(
                {"status": "failed_closed", "error_type": type(exc).__name__},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
