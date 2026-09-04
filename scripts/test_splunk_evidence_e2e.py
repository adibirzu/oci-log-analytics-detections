#!/usr/bin/env python3
"""Offline public-contract tests for the Splunk evidence exporter operator CLI."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest

from scripts.splunk_evidence_exporter import QueryWindow, build_evidence_event


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts/splunk_evidence_exporter_cli.py"
FIXTURES = ROOT / "scripts/fixtures/splunk_evidence"


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI), *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_json_plan_is_offline_complete_and_disabled_by_default():
    result = run_cli("plan", "--json")

    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan["offline"] is True
    assert plan["external_calls"] == []
    assert {mode["id"] for mode in plan["modes"]} == {"raw", "evidence"}
    assert all(mode["enabled_by_default"] is False for mode in plan["modes"])
    assert plan["detection_count"] == 9
    assert len(plan["detections"]) == 9
    assert plan["components"]
    assert plan["policy_categories"]
    assert plan["evidence_gates"]


def test_local_success_uses_service_and_commits_only_after_mock_hec_delivery():
    result = run_cli("local-e2e", "--scenario", "success")

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["scenario"] == "success"
    assert receipt["service"] == "EvidenceExportService"
    assert receipt["status"] == "delivered"
    assert receipt["query_row_count"] == receipt["delivered_count"] == 3
    assert receipt["mock_hec_event_count"] == 3
    assert receipt["checkpoint_committed"] is True
    assert receipt["operations"][-1] == "checkpoint_committed"
    assert receipt["evidence_class"] == "locally_verified"
    assert receipt["provider_validation"] == "not_run"
    assert receipt["scenario_counts"]["delivered"] == 3
    assert set(receipt["artifact_hashes"]) == {
        "scripts/fixtures/splunk_evidence/alarm.json",
        "scripts/fixtures/splunk_evidence/oci_raw_alarm.json",
        "scripts/fixtures/splunk_evidence/hec_responses.json",
        "scripts/fixtures/splunk_evidence/query_rows.json",
    }


def test_local_success_can_publish_normalized_evidence_to_streaming_for_oci_splunk():
    result = run_cli(
        "local-e2e", "--scenario", "success", "--delivery-target", "streaming"
    )

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["delivery_target"] == "streaming"
    assert receipt["mock_streaming_event_count"] == receipt["delivered_count"] == 3
    assert receipt["mock_hec_event_count"] == receipt["hec_attempt_count"] == 0
    assert receipt["delivery_attempt_count"] == 1
    assert receipt["scenario_counts"]["delivery_attempts"] == 1
    assert receipt["scenario_counts"]["hec_attempts"] == 0
    assert receipt["scenario_counts"]["streaming_attempts"] == 1
    assert "mock_streaming_delivered" in receipt["operations"]
    assert receipt["checkpoint_committed"] is True


def test_checked_in_provider_raw_alarm_fixture_is_accepted_without_a_custom_detection_id():
    result = run_cli("validate-payload", "--file", "scripts/fixtures/splunk_evidence/oci_raw_alarm.json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["alarm_id"] == "redacted-alarm-id"
    assert payload["detection_id"] is None


def test_cli_local_e2e_runs_provider_raw_alarm_through_bound_export_and_checkpoint():
    result = run_cli("local-e2e", "--scenario", "success", "--alarm-fixture", "scripts/fixtures/splunk_evidence/oci_raw_alarm.json")
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["alarm_fixture"] == "oci_raw_alarm.json"
    assert receipt["status"] == "delivered"
    assert receipt["hec_attempt_count"] == 1
    assert receipt["mock_hec_event_count"] == receipt["delivered_count"] == 3
    assert receipt["checkpoint_committed"] is True


@pytest.mark.parametrize(
    ("scenario", "status", "reason", "attempts"),
    [
        ("zero-evidence", "no_evidence", None, 0),
        ("timeout", "delivery_failed", "retryable", 4),
        ("429", "delivery_failed", "retryable", 4),
        ("500", "delivery_failed", "retryable", 4),
        ("400", "delivery_failed", "quarantine", 1),
        ("401", "delivery_failed", "quarantine", 1),
        ("oversized-batch", "delivery_failed", "quarantine", 1),
        ("missing-secret", "delivery_failed", "quarantine", 1),
        ("dlq-write", "delivery_failed", "retryable", 4),
        ("retry-exhaustion", "delivery_failed", "retryable", 4),
    ],
)
def test_local_failure_matrix_is_bounded_sanitized_and_fail_closed(
    scenario: str, status: str, reason: str | None, attempts: int
):
    result = run_cli("local-e2e", "--scenario", scenario)

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["service"] == "EvidenceExportService"
    assert receipt["status"] == status
    assert receipt["checkpoint_committed"] is False
    assert receipt["hec_attempt_count"] == attempts
    assert receipt["operations"].count("mock_hec_attempted") == attempts
    if reason is None:
        assert receipt["dlq_record_count"] == 0
        assert receipt["operations"][-1] == "query_executed"
    else:
        assert receipt["dlq_record_count"] == 1
        assert receipt["dlq_reason"] == reason
        assert receipt["operations"][-1] == "dlq_written"
    captured = result.stdout + result.stderr
    assert "sensitive-marker-never-print" not in captured
    assert "raw-provider-identifier-never-print" not in captured
    assert "oci" + "d1." not in captured


def test_duplicate_invocation_retains_stable_keys_and_reports_at_least_once_delivery():
    result = run_cli("local-e2e", "--scenario", "duplicate-invocation")

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "no_evidence"
    assert receipt["invocation_count"] == 2
    assert receipt["hec_attempt_count"] == 1
    assert receipt["stable_event_keys"] is True
    assert receipt["duplicate_event_count"] == 0
    assert receipt["checkpoint_committed"] is False


def test_service_visible_retry_succeeds_before_budget_and_then_commits():
    result = run_cli("local-e2e", "--scenario", "success-after-retry")

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "delivered"
    assert receipt["hec_attempt_count"] == 3
    assert receipt["mock_hec_event_count"] == 3
    assert receipt["checkpoint_committed"] is True
    assert receipt["operations"][-1] == "checkpoint_committed"


def test_dlq_failure_exits_nonzero_with_only_a_sanitized_fail_closed_error():
    result = run_cli("local-e2e", "--scenario", "dlq-failure")

    assert result.returncode == 1
    assert result.stdout == ""
    failure = json.loads(result.stderr)
    assert failure == {"error_type": "RuntimeError", "status": "failed_closed"}
    assert "sensitive-marker-never-print" not in result.stderr
    assert "raw-provider-identifier-never-print" not in result.stderr


def test_replay_requires_explicit_local_approval_and_uses_service_again():
    denied = run_cli("local-e2e", "--scenario", "approved-replay")
    approved = run_cli("local-e2e", "--scenario", "approved-replay", "--approve-replay")

    assert denied.returncode == 1
    assert json.loads(denied.stderr)["status"] == "failed_closed"
    assert approved.returncode == 0, approved.stderr
    receipt = json.loads(approved.stdout)
    assert receipt["initial_status"] == "delivery_failed"
    assert receipt["status"] == "delivered"
    assert receipt["replay_approved"] is True
    assert receipt["replayed_event_count"] == 3
    assert receipt["replay_matches_quarantined_events"] is True
    assert receipt["checkpoint_committed"] is True
    assert receipt["checkpoint_status"] == "advanced"
    assert receipt["service"] == "EvidenceReplayService"
    assert receipt["hec_attempt_count"] == 5
    assert receipt["operations"].count("query_executed") == 1


def test_offline_operator_commands_validate_and_render_without_external_calls():
    commands = {
        "validate-config": run_cli("validate-config"),
        "validate-payload": run_cli("validate-payload"),
        "render-function-config": run_cli("render-function-config"),
        "render-iam": run_cli("render-iam"),
        "canary-plan": run_cli("canary-plan"),
        "replay-plan": run_cli("replay-plan"),
    }

    for command, result in commands.items():
        assert result.returncode == 0, f"{command}: {result.stderr}"
        document = json.loads(result.stdout)
        assert document["offline"] is True
        assert document["external_calls"] == []

    assert json.loads(commands["validate-config"].stdout)["detection_count"] == 9
    assert json.loads(commands["validate-config"].stdout)["status"] == "valid"
    assert json.loads(commands["validate-payload"].stdout)["status"] == "valid"
    function_config = json.loads(commands["render-function-config"].stdout)
    assert function_config["enabled"] is False
    assert "SPLUNK_HEC_TOKEN" not in function_config["environment"]
    iam = json.loads(commands["render-iam"].stdout)
    assert iam["requires_scope_review"] is True
    assert iam["policy_categories"]
    for plan_name in ("canary-plan", "replay-plan"):
        plan = json.loads(commands[plan_name].stdout)
        assert plan["executes"] is False
        assert plan["approval_required"] is True
        assert plan["steps"]


def test_fixtures_are_deterministic_sanitized_and_build_schema_valid_events():
    alarm = json.loads((FIXTURES / "alarm.json").read_text(encoding="utf-8"))
    rows = json.loads((FIXTURES / "query_rows.json").read_text(encoding="utf-8"))
    hec_responses = json.loads(
        (FIXTURES / "hec_responses.json").read_text(encoding="utf-8")
    )
    registry = json.loads(
        (ROOT / "queries/splunk_detection_registry.json").read_text(encoding="utf-8")
    )
    schema = json.loads(
        (ROOT / "schemas/splunk_evidence_event.schema.json").read_text(encoding="utf-8")
    )
    entry = next(
        item
        for item in registry["detections"]
        if item["id"] == alarm["data"]["detectionId"]
    )
    window = QueryWindow(
        start=datetime(2026, 9, 2, 6, 58, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )

    validator = jsonschema.Draft202012Validator(schema)
    events = [
        build_evidence_event(entry, row, window, "fixture-batch").to_dict()
        for row in rows
    ]

    assert all(not list(validator.iter_errors(event)) for event in events)
    assert set(hec_responses) == {
        "success",
        "success-after-retry",
        "timeout",
        "429",
        "500",
        "400",
        "401",
        "oversized-batch",
    }
    fixture_text = " ".join(
        path.read_text(encoding="utf-8") for path in sorted(FIXTURES.glob("*.json"))
    )
    assert "oci" + "d1." not in fixture_text
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", fixture_text)
    assert not re.search(
        r'"(?:api[_-]?key|hec[_-]?token|password)"\s*:', fixture_text, re.I
    )


def test_payload_validation_rejects_unknown_identity_without_echoing_it(tmp_path):
    marker = "sensitive-marker-never-print"
    payload = {
        "data": {
            "detectionId": marker,
            "alarmEndTime": "2026-09-02T07:15:00Z",
            "namespace": "fixture-namespace",
            "metricName": "FixtureMetric",
            "dimensions": {"Entity": "raw-provider-identifier-never-print"},
        }
    }
    path = tmp_path / "alarm.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = run_cli("validate-payload", "--file", str(path))

    assert result.returncode == 1
    assert marker not in result.stdout + result.stderr
    assert "raw-provider-identifier-never-print" not in result.stdout + result.stderr
