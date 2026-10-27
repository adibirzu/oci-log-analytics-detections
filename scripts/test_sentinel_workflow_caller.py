"""Execute the YAML-selected post-promotion checker without live OCI actions."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import pytest
import yaml

from scripts.parser_contract import bind_query
from scripts.test_sentinel_compatibility import modern_tree

ROOT = Path(__file__).resolve().parents[1]


def promotion_step():
    workflow = yaml.safe_load((ROOT / ".github/workflows/sentinel-converter.yml").read_text())
    live = workflow["jobs"]["live"]
    return workflow, live, next(step for step in live["steps"] if step.get("name") == "Promote Sentinel conversions with live validation")


def python_commands(run):
    commands = []
    for line in run.replace("\\\n", " ").splitlines():
        words = shlex.split(line, comments=True)
        if words and words[0] in {"python", "python3"}:
            commands.append(words)
    return commands


def test_parsed_workflow_retains_live_authority_and_command_order():
    workflow, live, step = promotion_step()
    triggers = workflow.get("on", workflow.get(True))
    assert triggers["workflow_dispatch"]["inputs"]["profile"]["default"] == "cap"
    assert triggers["workflow_dispatch"]["inputs"]["lookback"]["default"] == "24h"
    assert workflow["jobs"]["live-preflight"]["if"] == "github.event_name == 'workflow_dispatch' || github.event_name == 'schedule'"
    assert live["if"] == "needs.live-preflight.outputs.credentials_available == 'true'"
    assert live["environment"] == "live-oci"
    assert live["permissions"] == {"contents": "read"}
    assert step["if"] == "steps.live-cache.outputs.cache-hit != 'true'"
    assert set(step["env"]) == {"OCI_PROFILE", "LOOKBACK", "LIVE_CACHE_KEY"}
    commands = python_commands(step["run"])
    assert commands[0][1:3] == ["scripts/sentinel_conversion_workflow.py", "promote"]
    assert commands[1][1] == "scripts/sentinel_drift_check.py"
    assert commands[2][1:3] == ["scripts/scan_sensitive_values.py", "--json"]


@pytest.mark.parametrize("tamper", [None, "query", "recomputed-query-binding", "missing-payload-binding", "missing-report-binding"])
def test_yaml_postpromotion_command_checks_bound_artifacts_without_restamping(tmp_path, tamper):
    _, _, step = promotion_step()
    command = next(words for words in python_commands(step["run"]) if words[1:2] == ["scripts/sentinel_drift_check.py"])
    # Only the checker selected by parsed YAML runs. Promotion and provider calls never run.
    command[0] = sys.executable
    for name in ["parser_contract.py", "sentinel_drift_check.py"]:
        target = tmp_path / "scripts" / name
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(ROOT / "scripts" / name, target)
    definition, payload, report = modern_tree(tmp_path)
    if tamper in {"query", "recomputed-query-binding"}:
        payload["query"] += " | head 1"
    if tamper == "recomputed-query-binding":
        payload["parser_contract"] = bind_query(definition, payload)
    if tamper == "missing-payload-binding":
        del payload["parser_contract"]
    if tamper == "missing-report-binding":
        del report["attempted"][0]["parser_contract"]
    inputs = {
        "queries/log_source_field_dictionary.json": definition,
        "queries/sentinel/example.json": payload,
        "queries/sentinel_conversion_report.json": report,
    }
    for name, value in inputs.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value))
    before = {name: (tmp_path / name).read_bytes() for name in inputs}
    result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == (0 if tamper is None else 1), result.stderr
    assert {name: (tmp_path / name).read_bytes() for name in inputs} == before
    if tamper is None:
        checked = json.loads((tmp_path / "queries/sentinel_drift.json").read_text())
        assert checked["summary"]["versioned_local_contract"] == 1
        assert checked["provider_revalidated"] is False
