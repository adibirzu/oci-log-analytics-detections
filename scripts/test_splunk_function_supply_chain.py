"""Public CLI contracts for the pre-live Function supply-chain gate."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import release_checklist


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts" / "verify_splunk_function_supply_chain.py"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _openssl(*args: str, cwd: Path) -> None:
    result = subprocess.run(["openssl", *args], cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode:
        pytest.fail(result.stderr)


def _attestation_fixture(tmp_path: Path, *, deployed_digest: str = "sha256:" + "a" * 64) -> tuple[Path, Path, Path]:
    staged = tmp_path / "staged"
    staged.mkdir()
    staged_file = staged / "func.py"
    staged_file.write_text("test-only staged source\n", encoding="utf-8")
    source_manifest = tmp_path / "build-context-manifest.json"
    _write_json(source_manifest, {"schema_version": "oci.logan.splunk.function-build-context.v1", "files": {"func.py": _digest(staged_file)}})
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
    private_key = tmp_path / "TEST_ONLY_private.pem"
    public_key = tmp_path / "TEST_ONLY_public.pem"
    _openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private_key), cwd=tmp_path)
    _openssl("pkey", "-in", str(private_key), "-pubout", "-out", str(public_key), cwd=tmp_path)
    provenance = tmp_path / "provenance.json"
    _write_json(
        provenance,
        {
            "schema_version": "oci.logan.splunk.function-build-provenance.v1",
            "subject": {"image_digest": deployed_digest},
            "builder": {"id": "test://oci-logan/supply-chain", "workflow_identity": "test-only-workflow"},
            "materials": {
                "source_manifest_sha256": _digest(source_manifest),
                "dependency_lock_sha256": _digest(lock),
                "sbom_sha256": _digest(sbom),
                "scan_receipt_sha256": {"sca": _digest(sca), "sast": _digest(sast), "iac": _digest(iac), "container": _digest(container)},
                "image_signature_receipt_sha256": _digest(signature),
            },
        },
    )
    provenance_signature = tmp_path / "provenance.sig"
    _openssl("dgst", "-sha256", "-sign", str(private_key), "-out", str(provenance_signature), str(provenance), cwd=tmp_path)
    trust_policy = tmp_path / "TEST_ONLY_trust_policy.json"
    _write_json(
        trust_policy,
        {
            "schema_version": "oci.logan.splunk.function-supply-chain-trust-policy.v1",
            "test_only": True,
            "trusted_signers": [{"key_id": "test-root", "public_key_path": public_key.name, "builder_id": "test://oci-logan/supply-chain", "workflow_identity": "test-only-workflow"}],
        },
    )
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
            "provenance": {"path": provenance.name, "sha256": _digest(provenance), "signature_path": provenance_signature.name, "signature_sha256": _digest(provenance_signature), "key_id": "test-root", "signature_algorithm": "openssl-dgst-sha256-rsa"},
        },
    )
    return attestation, trust_policy, staged


def _run(attestation: Path, digest: str, trust_policy: Path, staged: Path, *, allow_test_trust: bool = True, terraform_tfvars_out: Path | None = None) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(VERIFY), "--attestation", str(attestation), "--deployed-image-digest", digest, "--trust-policy", str(trust_policy), "--staged-build-context", str(staged)]
    if allow_test_trust:
        command.append("--allow-test-trust-policy")
    if terraform_tfvars_out:
        command.extend(["--terraform-tfvars-out", str(terraform_tfvars_out)])
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_pre_live_cli_accepts_hash_locked_transitively_complete_attestation(tmp_path: Path) -> None:
    digest = "sha256:" + "a" * 64
    attestation, trust_policy, staged = _attestation_fixture(tmp_path, deployed_digest=digest)
    result = _run(attestation, digest, trust_policy, staged)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "accepted_for_pre_live_gate"
    assert receipt["provider_validation"] == "not_run"
    assert receipt["external_calls"] == []


def test_pre_live_cli_emits_an_atomic_terraform_binding_for_the_verified_receipts(tmp_path: Path) -> None:
    digest = "sha256:" + "a" * 64
    attestation, trust_policy, staged = _attestation_fixture(tmp_path, deployed_digest=digest)
    output = tmp_path / "private" / "supply-chain.auto.tfvars.json"
    result = _run(attestation, digest, trust_policy, staged, terraform_tfvars_out=output)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert json.loads(output.read_text(encoding="utf-8")) == receipt["terraform_binding"]
    assert receipt["terraform_binding"]["splunk_evidence_exporter_function_image_digest"] == digest


def test_release_pre_live_workflow_invokes_the_signed_verifier_for_the_chosen_image(tmp_path: Path) -> None:
    digest = "sha256:" + "a" * 64
    attestation, trust_policy, staged = _attestation_fixture(tmp_path, deployed_digest=digest)
    # The release workflow must reject test-only policy material. Flip only
    # this temporary fixture to model a retained external trust policy.
    policy = json.loads(trust_policy.read_text(encoding="utf-8"))
    policy["test_only"] = False
    _write_json(trust_policy, policy)
    tfvars = tmp_path / "private" / "supply-chain.auto.tfvars.json"
    result = release_checklist.run_splunk_pre_live_supply_chain_gate(
        attestation=attestation,
        trust_policy=trust_policy,
        staged_build_context=staged,
        image_digest=digest,
        terraform_tfvars_out=tfvars,
    )
    assert result["status"] == "PASS"
    assert result["receipt"]["deployed_image_digest"] == digest
    assert json.loads(tfvars.read_text(encoding="utf-8"))["splunk_evidence_exporter_function_image_digest"] == digest


def test_pre_live_cli_fails_closed_for_missing_or_mismatched_receipts(tmp_path: Path) -> None:
    digest = "sha256:" + "a" * 64
    attestation, trust_policy, staged = _attestation_fixture(tmp_path, deployed_digest=digest)
    payload = json.loads(attestation.read_text(encoding="utf-8"))
    payload["signature"]["sha256"] = "0" * 64
    _write_json(attestation, payload)

    result = _run(attestation, digest, trust_policy, staged)
    assert result.returncode == 1
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "rejected"
    assert receipt["error_type"] == "SupplyChainVerificationError"


def test_pre_live_cli_rejects_local_example_even_when_its_files_match(tmp_path: Path) -> None:
    digest = "sha256:" + "a" * 64
    attestation, trust_policy, staged = _attestation_fixture(tmp_path, deployed_digest=digest)
    payload = json.loads(attestation.read_text(encoding="utf-8"))
    payload["example"] = True
    _write_json(attestation, payload)

    result = _run(attestation, digest, trust_policy, staged)
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "rejected"


@pytest.mark.parametrize("tamper", ["wrong_signer", "wrong_builder", "wrong_material", "wrong_digest", "forged_signature", "staged_source", "replaced_sbom_receipt", "replaced_scan_receipt", "replaced_image_signature_receipt"])
def test_pre_live_cli_rejects_untrusted_or_tampered_signed_provenance(tmp_path: Path, tamper: str) -> None:
    digest = "sha256:" + "a" * 64
    attestation, trust_policy, staged = _attestation_fixture(tmp_path, deployed_digest=digest)
    payload = json.loads(attestation.read_text(encoding="utf-8"))
    provenance = tmp_path / payload["provenance"]["path"]
    statement = json.loads(provenance.read_text(encoding="utf-8"))
    if tamper == "wrong_signer":
        payload["provenance"]["key_id"] = "not-approved"
    elif tamper == "wrong_builder":
        statement["builder"]["id"] = "untrusted-builder"
    elif tamper == "wrong_material":
        statement["materials"]["dependency_lock_sha256"] = "0" * 64
    elif tamper == "wrong_digest":
        statement["subject"]["image_digest"] = "sha256:" + "b" * 64
    elif tamper == "forged_signature":
        (tmp_path / payload["provenance"]["signature_path"]).write_bytes(b"forged")
        payload["provenance"]["signature_sha256"] = _digest(tmp_path / payload["provenance"]["signature_path"])
    elif tamper == "replaced_sbom_receipt":
        sbom_path = tmp_path / payload["sbom"]["path"]
        receipt = json.loads(sbom_path.read_text(encoding="utf-8"))
        receipt["replaced"] = True
        _write_json(sbom_path, receipt)
        payload["sbom"]["sha256"] = _digest(sbom_path)
    elif tamper == "replaced_scan_receipt":
        scan_descriptor = next(scan for scan in payload["scans"] if scan["type"] == "sca")
        scan_path = tmp_path / scan_descriptor["path"]
        receipt = json.loads(scan_path.read_text(encoding="utf-8"))
        receipt["replaced"] = True
        _write_json(scan_path, receipt)
        scan_descriptor["sha256"] = _digest(scan_path)
    elif tamper == "replaced_image_signature_receipt":
        signature_receipt = tmp_path / payload["signature"]["path"]
        receipt = json.loads(signature_receipt.read_text(encoding="utf-8"))
        receipt["replaced"] = True
        _write_json(signature_receipt, receipt)
        payload["signature"]["sha256"] = _digest(signature_receipt)
    else:
        (staged / "func.py").write_text("tampered\n", encoding="utf-8")
    if tamper in {"wrong_builder", "wrong_material", "wrong_digest"}:
        _write_json(provenance, statement)
        payload["provenance"]["sha256"] = _digest(provenance)
    _write_json(attestation, payload)
    result = _run(attestation, digest, trust_policy, staged)
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "rejected"


def test_test_only_trust_policy_requires_explicit_local_override(tmp_path: Path) -> None:
    digest = "sha256:" + "a" * 64
    attestation, trust_policy, staged = _attestation_fixture(tmp_path, deployed_digest=digest)
    result = _run(attestation, digest, trust_policy, staged, allow_test_trust=False)
    assert result.returncode == 1
