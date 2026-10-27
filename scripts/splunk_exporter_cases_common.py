#!/usr/bin/env python3
"""Public-contract tests for the pure Splunk evidence exporter domain."""

import ast
import base64
import io
import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

from scripts.splunk_evidence_exporter.adapters import (
    OciLogAnalyticsQueryAdapter,
    OciStreamingEvidenceAdapter,
    OciVaultSecretAdapter,
    ObjectStorageDeadLetterAdapter,
    ObjectStorageStateAdapter,
    SplunkHecAdapter,
    _validated_streaming_endpoint,
)

from scripts.splunk_evidence_exporter import (
    AlarmTrigger,
    EvidenceEvent,
    ExportBatch,
    QueryWindow,
    batch_events,
    build_evidence_event,
    calculate_window,
    classify_hec_failure,
    event_key,
)
from scripts.splunk_evidence_exporter.ports import (
    CheckpointPort,
    EvidenceQueryPort,
    HecDeliveryPort,
    QuarantinePort,
)
from scripts.splunk_evidence_exporter.service import (
    EvidenceExportService,
    EvidenceReplayService,
)
from scripts.splunk_evidence_exporter import handler as handler_module


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_VALIDATOR = jsonschema.Draft202012Validator(
    json.loads((ROOT / "schemas/splunk_evidence_event.schema.json").read_text())
)


def alarm_payload(**overrides):
    data = {
        "detectionId": "oci-audit-failures",
        "alarmEndTime": "2026-09-02T07:15:00Z",
        "namespace": "oci_log_analytics_detections",
        "metricName": "AuditFailures",
        "dimensions": {
            "Event Type": "com.oraclecloud.identitycontrolplane.updatepolicy",
            "User Name": "operator@example.invalid",
            "Status": "Failure",
        },
    }
    data.update(overrides)
    return {"type": "com.oraclecloud.monitoring.alarm", "data": data}


def registry_entry():
    return {
        "id": "oci-audit-failures",
        "title": "OCI Audit Failures",
        "oci_query_file": "queries/hunting/oci_audit_failures.json",
        "query_version": "a" * 64,
        "required_sources": ["OCI Audit Logs"],
        "required_fields": [
            "Event Type", "Status", "Evidence Version", "api_token", "Password Hash", "Authorization",
            "clientSecret", "Resource OCID", "Customer Field", "Details",
        ],
        "detection": {"severity": "medium", "mitre_techniques": ["T1078"], "mechanism": "scheduled"},
        "delivery": {"evidence_targets": ["hec", "streaming"]},
        "alarm_contract": {
            "metric_namespace": "oci_log_analytics_detections",
            "metric_dimensions": ["Event Type", "Status"],
        },
        "evidence": {"include_original_content": False, "redaction_profile": None},
    }
