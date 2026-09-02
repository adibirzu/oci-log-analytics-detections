"""Public CLI contracts for the pre-live Function supply-chain gate."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts" / "verify_splunk_function_supply_chain.py"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _attestation_fixture(tmp_path: Path, *, deployed_digest: str = "sha256:" + "a" * 64) -> Path:
    source_manifest = tmp_path / "build-context-manifest.json"
    _write_json(source_manifest, {"schema_version": "oci.logan.splunk.function-build-context.v1", "files": {"func.py": "a" * 64}})
    lock = tmp_path / "requirements-hashed.lock"
    lock.write_text(
        "fdk==0.1.90 \\\n+    --hash=sha256:" + "1" * 64 + "\n"
        "oci==2.160.3 \\\n+    --hash=sha256:" + "2" * 64 + "\n"
        "certifi==2026.1.1 \\\n+    --hash=sha256:" + "3" * 64 + "\n",
        encoding="utf-8",
    )
    shared = {
        "image_digest": deployed_digest,
        "source_manifest_sha256": _digest(source_manifest),
        "dependency_lock_sha256": _digest(lock),
    }
    sbom = tmp_path / "sbom.json"
    _write_json(sbom, {**shared, "component_count": 3})
    sca = tmp_path / "sca.json"
    _write_json(sca, {**shared, "result": "pass"})
    sast = tmp_path / "sast.json"
    _write_json(sast, {**shared, "result": "pass"})
    iac = tmp_path / "iac.json"
    _write_json(iac, {**shared, "result": "pass"})
    container = tmp_path / "container.json"
    _write_json(container, {**shared, "result": "pass"})
    signature = tmp_path / "signature.json"
    _write_json(signature, {**shared, "verified": True, "subject_digest": deployed_digest})
    attestation = tmp_path / "attestation.json"
    _write_json(
        attestation,
        {
            "schema_version": "oci.logan.splunk.function-supply-chain-attestation.v1",
            "receipt_type": "external_pre_live_attestation",
            "evidence_class": "externally_verified",
            "example": False,
            "deployed_image": {"reference": "iad.ocir.io/example/logan/splunk-exporter", "digest": deployed_digest},
            "source_manifest": {"path": source_manifest.name, "sha256": _digest(source_manifest)},
            "dependency_lock": {
                "path": lock.name,
                "sha256": _digest(lock),
                "direct_dependency_count": 2,
                "transitive_dependency_count": 1,
            },
            "sbom": {"path": sbom.name, "sha256": _digest(sbom)},
            "scans": [
                {"type": "sca", "path": sca.name, "sha256": _digest(sca)},
                {"type": "sast", "path": sast.name, "sha256": _digest(sast)},
                {"type": "iac", "path": iac.name, "sha256": _digest(iac)},
                {"type": "container", "path": container.name, "sha256": _digest(container)},
            ],
            "signature": {"path": signature.name, "sha256": _digest(signature)},
        },
    )
    return attestation


def _run(attestation: Path, digest: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFY), "--attestation", str(attestation), "--deployed-image-digest", digest],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_pre_live_cli_accepts_hash_locked_transitively_complete_attestation(tmp_path: Path) -> None:
    digest = "sha256:" + "a" * 64
    result = _run(_attestation_fixture(tmp_path, deployed_digest=digest), digest)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "accepted_for_pre_live_gate"
    assert receipt["provider_validation"] == "not_run"
    assert receipt["external_calls"] == []


def test_pre_live_cli_fails_closed_for_missing_or_mismatched_receipts(tmp_path: Path) -> None:
    digest = "sha256:" + "a" * 64
    attestation = _attestation_fixture(tmp_path, deployed_digest=digest)
    payload = json.loads(attestation.read_text(encoding="utf-8"))
    payload["signature"]["sha256"] = "0" * 64
    _write_json(attestation, payload)

    result = _run(attestation, digest)
    assert result.returncode == 1
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "rejected"
    assert receipt["error_type"] == "SupplyChainVerificationError"


def test_pre_live_cli_rejects_local_example_even_when_its_files_match(tmp_path: Path) -> None:
    digest = "sha256:" + "a" * 64
    attestation = _attestation_fixture(tmp_path, deployed_digest=digest)
    payload = json.loads(attestation.read_text(encoding="utf-8"))
    payload["example"] = True
    _write_json(attestation, payload)

    result = _run(attestation, digest)
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "rejected"
