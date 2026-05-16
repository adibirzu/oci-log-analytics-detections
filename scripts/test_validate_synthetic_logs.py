#!/usr/bin/env python3
"""Tests for synthetic log contract validation."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from validate_synthetic_logs import validate_all, validate_contract


class TestValidateSyntheticLogs(unittest.TestCase):
    """Ensure schema contracts catch drift and enforce provider coverage."""

    def test_validate_contract_accepts_matching_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dataset = Path(tmpdir) / "application_logs.jsonl"
            dataset.write_text(
                json.dumps({
                    "timestamp": "2026-04-22T10:00:00.000Z",
                    "serviceName": "enterprise-crm-portal",
                    "traceId": "trace_abc123",
                    "requestUrl": "/crm/login",
                    "statusCode": "200",
                    "clientAddress": "10.0.0.5",
                    "spanName": "HTTP GET /crm/login",
                    "message": "Request completed",
                }) + "\n"
            )
            contract = {
                "required_fields": [
                    "timestamp",
                    "serviceName",
                    "traceId",
                    "requestUrl",
                    "statusCode",
                    "clientAddress",
                    "spanName",
                    "message",
                ],
                "field_patterns": {
                    "traceId": "^trace_",
                    "statusCode": "^\\d{3}$",
                },
                "required_values": {
                    "serviceName": ["enterprise-crm-portal"]
                }
            }

            self.assertEqual(validate_contract(dataset, contract), [])

    def test_validate_contract_flags_missing_required_values_and_conditional_patterns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dataset = Path(tmpdir) / "multicloud_health.jsonl"
            dataset.write_text(
                "\n".join([
                    json.dumps({
                        "Timestamp": "2026-04-22T10:00:00.000Z",
                        "Cloud Provider": "OCI",
                        "Region": "us-ashburn-1",
                        "Region Display": "US East (Ashburn)",
                        "Latitude": 39.0,
                        "Longitude": -77.4,
                        "Instance ID": "bad-oci-id",
                        "Host Name": "host-1",
                        "Status": "healthy",
                        "Heartbeat Sequence": 1,
                        "Log Source": "SOC Multicloud Health Logs"
                    }),
                    json.dumps({
                        "Timestamp": "2026-04-22T10:01:00.000Z",
                        "Cloud Provider": "AWS",
                        "Region": "us-east-1",
                        "Region Display": "US East (N. Virginia)",
                        "Latitude": 38.9,
                        "Longitude": -77.0,
                        "Instance ID": "i-1234567890abcdef0",
                        "Host Name": "host-2",
                        "Status": "healthy",
                        "Heartbeat Sequence": 1,
                        "Log Source": "SOC Multicloud Health Logs"
                    })
                ]) + "\n"
            )
            contract = {
                "required_fields": [
                    "Timestamp",
                    "Cloud Provider",
                    "Instance ID",
                    "Log Source"
                ],
                "required_values": {
                    "Cloud Provider": ["OCI", "AWS", "Azure"]
                },
                "conditional_patterns": [
                    {
                        "when": {"Cloud Provider": "OCI"},
                        "field_patterns": {"Instance ID": "^ocid1\\.instance\\."}
                    }
                ]
            }

            errors = validate_contract(dataset, contract)
            self.assertTrue(any("conditional pattern" in error for error in errors))
            self.assertTrue(any("missing required values" in error for error in errors))

    def test_validate_all_reports_missing_dataset(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_data_dir = Path(tmpdir) / "test_data"
            test_data_dir.mkdir()
            contracts_path = Path(tmpdir) / "contracts.json"
            contracts_path.write_text(json.dumps({
                "missing.jsonl": {
                    "required_fields": ["foo"]
                }
            }))

            report = validate_all(test_data_dir=test_data_dir, contracts_path=contracts_path)
            self.assertFalse(report["ok"])
            self.assertIn("missing.jsonl", report["results"])

    def test_validate_all_rejects_generated_support_artifact_contract(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_data_dir = Path(tmpdir) / "test_data"
            test_data_dir.mkdir()
            contracts_path = Path(tmpdir) / "contracts.json"
            contracts_path.write_text(json.dumps({
                "sentinel_synthetic_plan.json": {
                    "required_fields": ["summary"]
                }
            }))

            report = validate_all(test_data_dir=test_data_dir, contracts_path=contracts_path)

            self.assertFalse(report["ok"])
            self.assertIn("sentinel_synthetic_plan.json", report["results"])
            self.assertEqual(report["total_errors"], 1)
            self.assertTrue(
                any(
                    "generated support artifact" in error
                    for error in report["results"]["sentinel_synthetic_plan.json"]["errors"]
                )
            )

    def test_web_to_cloud_network_contracts_are_registered(self):
        contracts_path = Path(__file__).resolve().parents[1] / "config" / "synthetic_log_contracts.json"

        with contracts_path.open() as f:
            contracts = json.load(f)

        self.assertIn("vcn_flow.jsonl", contracts)
        self.assertIn("network_firewall.jsonl", contracts)
        self.assertIn("data.srcaddr", contracts["vcn_flow.jsonl"]["required_nested_fields"])
        self.assertIn("data.bytesOut", contracts["vcn_flow.jsonl"]["required_nested_fields"])
        self.assertIn("logContent.data.src_ip", contracts["network_firewall.jsonl"]["required_nested_fields"])
        self.assertIn("logContent.data.threat_name", contracts["network_firewall.jsonl"]["required_nested_fields"])


if __name__ == "__main__":
    unittest.main()
