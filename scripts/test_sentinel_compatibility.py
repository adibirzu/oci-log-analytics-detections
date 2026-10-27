"""Exercise real offline CLI consumption, including a checkout without Git."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import copy
import hashlib
import pytest

from scripts.parser_contract import bind_query
from scripts.test_parser_contract import dictionary

ROOT = Path(__file__).resolve().parents[1]


def modern_tree(tmp_path):
    d = dictionary()
    p = {"title": "Synthetic", "query": "'User' = 'synthetic'", "sentinel_id": "synthetic-rule", "sentinel_source_path": "synthetic/rule.yaml", "source_type": "microsoft_sentinel", "conversion_status": "promoted", "live_validation_status": "passed"}
    p["parser_schema_hash"] = hashlib.sha256(json.dumps({k: v for k, v in d.items() if k != "generated_at"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    p["parser_contract"] = bind_query(d, p)
    row = {"output_file": "sentinel/example.json", "sentinel_id": p["sentinel_id"], "source_path": p["sentinel_source_path"], "live_validation_status": "passed", "parser_contract": copy.deepcopy(p["parser_contract"])}
    report = {"summary": {"promoted_count": 1, "live_validation_passed": 1}, "attempted": [row]}
    return d, p, report


def run_fixture(tmp_path, d, p, report, *extra):
    source = tmp_path / "sentinel"
    source.mkdir(exist_ok=True)
    (source / "example.json").write_text(json.dumps(p))
    (tmp_path / "dictionary.json").write_text(json.dumps(d))
    (tmp_path / "report.json").write_text(json.dumps(report))
    return subprocess.run([sys.executable, str(ROOT / "scripts/sentinel_drift_check.py"), "--sentinel-dir", str(source), "--dictionary", str(tmp_path / "dictionary.json"), "--report", str(tmp_path / "report.json"), "--legacy-manifest", str(tmp_path / "missing-manifest.json"), "--output", str(tmp_path / "result.json"), *extra], capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


def test_recomputing_query_binding_cannot_inherit_old_report_acceptance(tmp_path):
    d, p, report = modern_tree(tmp_path)
    p["query"] += " | head 1"
    p["parser_contract"] = bind_query(d, p)
    assert run_fixture(tmp_path, d, p, report).returncode == 1


def test_versioned_local_binding_and_usage_only_changes_are_accepted(tmp_path):
    d, p, report = modern_tree(tmp_path)
    d["fields"][0]["queries_using_it"] = ["hunting/new-query.json"]
    assert run_fixture(tmp_path, d, p, report).returncode == 0
    result = json.loads((tmp_path / "result.json").read_text())
    assert result["summary"]["versioned_local_contract"] == 1
    assert result["provider_revalidated"] is False


@pytest.mark.parametrize("tamper", ["query", "identity", "report-binding", "report-status", "missing-report-row", "duplicate-report-output", "unknown-version", "unknown-dictionary-key", "type-change", "mapping-change", "missing-hash", "unbound-legacy"])
def test_cli_fails_closed_for_unknown_or_changed_bindings(tmp_path, tamper):
    d, p, report = modern_tree(tmp_path)
    if tamper == "query": p["query"] += " | head 1"
    if tamper == "identity": p["sentinel_id"] = "changed"
    if tamper == "report-binding": del report["attempted"][0]["parser_contract"]
    if tamper == "report-status": report["attempted"][0]["live_validation_status"] = "not_run"
    if tamper == "missing-report-row": report["attempted"] = []
    if tamper == "duplicate-report-output": report["attempted"].append(copy.deepcopy(report["attempted"][0]))
    if tamper == "unknown-version": p["parser_contract"]["schema_version"] = "unknown"
    if tamper == "unknown-dictionary-key": d["unexpected_structure"] = "must not appear in errors"
    if tamper == "type-change": d["fields"][0]["type"] = "NUMBER"
    if tamper == "mapping-change": d["fields"][0]["raw_json_paths"] = ["$.other"]
    if tamper == "missing-hash": del p["parser_schema_hash"]
    if tamper == "unbound-legacy": del p["parser_contract"]
    result = run_fixture(tmp_path, d, p, report)
    assert result.returncode == 1
    assert "must not appear" not in result.stdout + result.stderr


def test_restamp_cli_refuses_without_mutating_any_accepted_file(tmp_path):
    d, p, report = modern_tree(tmp_path)
    result = run_fixture(tmp_path, d, p, report, "--write-hashes")
    assert result.returncode == 1
    assert json.loads((tmp_path / "sentinel/example.json").read_text()) == p
    assert "invalid local binding" in result.stderr


def test_malformed_dictionary_has_fixed_safe_cli_error(tmp_path):
    d, p, report = modern_tree(tmp_path)
    result = run_fixture(tmp_path, [], p, report)
    assert result.returncode == 1
    assert result.stderr == "Sentinel compatibility check failed; invalid local binding\n"


def test_actual_producer_report_and_consumer_bind_the_same_query(tmp_path):
    from scripts.convert_sentinel_kql import build_query_payload, ConversionResult
    from scripts.sentinel_converter_reporting import build_conversion_report

    # Synthetic in-memory validation result only; this test never calls OCI.
    candidate = {"sentinel_id": "synthetic-rule", "source_path": "synthetic/rule.yaml", "title": "Synthetic"}
    payload = build_query_payload(candidate, "'User' = 'synthetic'", {}, "passed")
    result = ConversionResult(candidate=candidate, query_payload=payload, skip_reasons=[], local_validation_errors=[], live_validation_result={"ok": True}, output_file="sentinel/example.json")
    report = build_conversion_report([candidate], [candidate], [result], {}, True)
    definition = json.loads((ROOT / "queries/log_source_field_dictionary.json").read_text())
    assert run_fixture(tmp_path, definition, payload, report).returncode == 0
    payload["query"] += " | head 1"
    payload["parser_contract"] = bind_query(definition, payload)
    assert run_fixture(tmp_path, definition, payload, report).returncode == 1


def test_shallow_export_uses_only_reviewed_bindings_and_rejects_tampering(tmp_path):
    export = tmp_path / "export"
    for name in ["scripts/parser_contract.py", "scripts/sentinel_drift_check.py", "config/sentinel_legacy_compatibility_v1.json", "queries/log_source_field_dictionary.json", "queries/sentinel_conversion_report.json"]:
        target = export / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    shutil.copytree(ROOT / "queries/sentinel", export / "queries/sentinel")
    command = [sys.executable, str(export / "scripts/sentinel_drift_check.py"), "--output", str(tmp_path / "shallow-result.json")]
    assert not (export / ".git").exists()
    assert subprocess.run(command, capture_output=True).returncode == 0
    target = next((export / "queries/sentinel").glob("*.json"))
    original = target.read_bytes()
    payload = json.loads(original)
    payload["query"] += " | head 1"
    target.write_text(json.dumps(payload))
    assert subprocess.run(command, capture_output=True).returncode == 1
    target.write_bytes(original)
    manifest = export / "config/sentinel_legacy_compatibility_v1.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")
    assert subprocess.run(command, capture_output=True).returncode == 1
    manifest.unlink()
    assert subprocess.run(command, capture_output=True).returncode == 1


def test_generator_cannot_manufacture_bindings_in_shallow_ci(tmp_path):
    export = tmp_path / "export"
    (export / "scripts").mkdir(parents=True)
    for name in ["parser_contract.py", "generate_sentinel_compatibility.py"]:
        shutil.copyfile(ROOT / "scripts" / name, export / "scripts" / name)
    result = subprocess.run([sys.executable, str(export / "scripts/generate_sentinel_compatibility.py"), "--check"], capture_output=True, text=True)
    assert result.returncode == 1
    assert not (export / "config/sentinel_legacy_compatibility_v1.json").exists()
    assert "fixed source binding unavailable" in result.stderr


def test_actual_590_gate_is_local_source_compatibility_not_a_provider_receipt(tmp_path):
    output = tmp_path / "drift.json"
    run = subprocess.run([sys.executable, str(ROOT / "scripts/sentinel_drift_check.py"), "--output", str(output)], cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert run.returncode == 0, run.stdout[-1000:]
    report = json.loads(output.read_text())
    assert report["summary"]["promoted_files"] == 590
    assert report["summary"]["legacy_source_compatible"] == 590
    assert report["evidence_class"] == "locally_verified_compatibility"
    assert report["provider_revalidated"] is False
    assert all(row["legacy_raw_hash_status"] == "unresolved_preserved" for row in report["current"])
