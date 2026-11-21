"""Unit and contract tests for deterministic Log Analytics content manifest."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_content_manifest import validate_content_manifest
from query_artifacts import is_generated_query_artifact, is_saved_search_query_file

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = Path("queries/content_manifest.json")
SCHEMA_PATH = ROOT / "schemas" / "content_manifest.schema.json"


def _seed_mini_repo(root: Path) -> None:
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "scripts" / "generate_content_manifest.py", root / "scripts" / "generate_content_manifest.py")
    shutil.copyfile(ROOT / "scripts" / "query_artifacts.py", root / "scripts" / "query_artifacts.py")

    (root / "schemas").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SCHEMA_PATH, root / "schemas" / "content_manifest.schema.json")

    (root / "queries" / "apps").mkdir(parents=True, exist_ok=True)
    (root / "queries" / "hunting").mkdir(parents=True, exist_ok=True)
    (root / "queries" / "sentinel").mkdir(parents=True, exist_ok=True)
    (root / "queries" / "sample_detection.json").write_text(
        json.dumps(
            {
                "title": "Sample Detection",
                "query": "'Log Source' = 'OCI Audit Logs'",
                "level": "high",
                "logsource": {"product": "oci", "service": "audit"},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "queries" / "apps" / "sample_app.json").write_text(
        json.dumps(
            {
                "title": "Sample App Query",
                "query": "'Log Source' = 'SOC Application Logs'",
                "level": "medium",
                "logsource": {"product": "application", "service": "soc_application_logs"},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "queries" / "hunting" / "sample_hunt.json").write_text(
        json.dumps(
            {
                "title": "Sample Hunt",
                "query": "'Log Source' = 'OCI VCN Flow Logs' | stats count",
                "level": "informational",
                "logsource": {"product": "oci", "service": "vcn"},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "queries" / "sentinel" / "sample_sentinel.json").write_text(
        json.dumps(
            {
                "title": "Sample Sentinel",
                "query": "'Log Source' = 'Azure Activity Logs'",
                "level": "medium",
                "source_type": "microsoft_sentinel",
                "logsource": {"product": "microsoft_sentinel", "service": "azure"},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "queries" / "dashboard_inventory.json").write_text(
        json.dumps(
            {
                "version": "1.0",
                "dashboards": [
                    {
                        "name": "SOC Overview Dashboard",
                        "widget_count": 1,
                        "widgets": [{"title": "W1", "query_file": "sample_detection.json"}],
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    (root / "rules" / "cloud" / "oci").mkdir(parents=True, exist_ok=True)
    (root / "rules" / "cloud" / "oci" / "sample_rule.yaml").write_text(
        "id: 11111111-1111-1111-1111-111111111111\ntitle: Sample Rule\nlevel: high\nlogsource:\n  product: oci\ndetection:\n  selection:\n    eventName: DeleteBucket\n  condition: selection\n",
        encoding="utf-8",
    )

    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config" / "hunting_packs.json").write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "packs": [
                    {
                        "id": "sample_pack",
                        "title": "Sample Pack",
                        "query_paths": ["hunting/sample_hunt.json"],
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "dashboards").mkdir(parents=True, exist_ok=True)
    (root / "dashboards" / "sample_dashboard.json").write_text(
        json.dumps({"name": "Sample External Dashboard", "widgets": []}) + "\n",
        encoding="utf-8",
    )


def test_content_manifest_is_not_saved_search_query():
    assert is_generated_query_artifact("queries/content_manifest.json")
    assert not is_saved_search_query_file("queries/content_manifest.json")


def test_content_manifest_deterministic_generation_and_drift_detection(tmp_path):
    _seed_mini_repo(tmp_path)

    def run(mode: str, hash_seed: int):
        return subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(tmp_path / "scripts" / "generate_content_manifest.py"),
                mode,
                "--root",
                str(tmp_path),
            ],
            cwd=tmp_path,
            env={**os.environ, "PYTHONHASHSEED": str(hash_seed)},
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    artifact = tmp_path / ARTIFACT
    # Missing manifest fails --check (RED)
    missing = run("--check", 1)
    assert missing.returncode == 1
    assert not artifact.exists()

    # --write succeeds and is byte-identical across PYTHONHASHSEEDs
    write_1 = run("--write", 1)
    assert write_1.returncode == 0, write_1.stderr
    first_bytes = artifact.read_bytes()

    write_2 = run("--write", 2)
    assert write_2.returncode == 0, write_2.stderr
    assert artifact.read_bytes() == first_bytes
    assert run("--check", 3).returncode == 0

    manifest = json.loads(first_bytes.decode("utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert validate_content_manifest(manifest, schema=schema) == []

    assert manifest["summary"]["total_queries"] == 4
    assert manifest["summary"]["total_rules"] == 1
    assert manifest["summary"]["total_packs"] >= 1
    assert manifest["summary"]["total_dashboards"] == 2
    assert len(manifest["content_digest"]) == 64

    # Drift in a query invalidates --check without mutating artifact
    (tmp_path / "queries" / "sample_detection.json").write_text(
        json.dumps({"title": "Modified", "query": "'Log Source' = 'OCI Audit Logs'", "level": "low"}) + "\n",
        encoding="utf-8",
    )
    drifted = run("--check", 4)
    assert drifted.returncode == 1
    assert "out of date" in drifted.stderr.lower()
    assert artifact.read_bytes() == first_bytes

    assert run("--write", 5).returncode == 0
    assert run("--check", 6).returncode == 0


def test_checked_in_content_manifest_matches_repo_and_schema():
    manifest_path = ROOT / ARTIFACT
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert validate_content_manifest(manifest, schema=schema) == []

    check = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_content_manifest.py"), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert check.returncode == 0, check.stderr
