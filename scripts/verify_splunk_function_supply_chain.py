#!/usr/bin/env python3
"""Fail-closed, offline verifier for a Splunk Function pre-live attestation.

The verifier does not build, pull, scan, sign, or deploy an image.  It checks
that externally produced receipts describe the same staged source manifest,
hash-locked dependency resolution, immutable deployed image digest, SBOM,
scans, and signature before a separate approved live release action.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parent.parent
FUNCTION_REQUIREMENTS = ROOT / "stack/modules/splunk_evidence_exporter/function/requirements.txt"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PACKAGE_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\\\s]+)")
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})")
REQUIRED_SCAN_TYPES = frozenset({"sca", "sast", "iac", "container"})


class SupplyChainVerificationError(ValueError):
    """An attestation cannot safely authorize a pre-live release gate."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupplyChainVerificationError("receipt is unreadable") from exc
    if not isinstance(value, Mapping):
        raise SupplyChainVerificationError("receipt must be a JSON object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SupplyChainVerificationError(f"{label} is required")
    return value


def _digest(value: object, label: str) -> str:
    candidate = _string(value, label)
    if not DIGEST_RE.fullmatch(candidate):
        raise SupplyChainVerificationError(f"{label} must be an immutable sha256 digest")
    return candidate


def _relative_receipt_path(base: Path, value: object, label: str) -> Path:
    relative = Path(_string(value, label))
    if relative.is_absolute() or ".." in relative.parts:
        raise SupplyChainVerificationError(f"{label} must be relative to the attestation")
    path = (base / relative).resolve()
    if base != path and base not in path.parents:
        raise SupplyChainVerificationError(f"{label} escapes the attestation directory")
    if not path.is_file():
        raise SupplyChainVerificationError(f"{label} is missing")
    return path


def _receipt_file(base: Path, descriptor: object, label: str) -> tuple[Path, Mapping[str, Any]]:
    if not isinstance(descriptor, Mapping):
        raise SupplyChainVerificationError(f"{label} descriptor is required")
    path = _relative_receipt_path(base, descriptor.get("path"), f"{label}.path")
    expected_hash = _string(descriptor.get("sha256"), f"{label}.sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise SupplyChainVerificationError(f"{label}.sha256 is invalid")
    if _sha256(path) != expected_hash:
        raise SupplyChainVerificationError(f"{label} content hash does not match")
    return path, _read_json(path)


def _hashed_file(base: Path, relative: object, expected_hash: object, label: str) -> Path:
    path = _relative_receipt_path(base, relative, label)
    expected = _string(expected_hash, f"{label}.sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or _sha256(path) != expected:
        raise SupplyChainVerificationError(f"{label} content hash does not match")
    return path


def _verify_staged_source(source_manifest: Mapping[str, Any], staged_context: Path) -> None:
    files = source_manifest.get("files")
    if not isinstance(files, Mapping) or not files:
        raise SupplyChainVerificationError("source manifest is not a populated staged Function manifest")
    root = staged_context.resolve()
    if not root.is_dir():
        raise SupplyChainVerificationError("staged build context is unavailable")
    for relative, expected in files.items():
        if not isinstance(relative, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", relative):
            raise SupplyChainVerificationError("source manifest contains an unsafe staged path")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise SupplyChainVerificationError("source manifest contains an invalid file hash")
        candidate = (root / relative).resolve()
        if root not in candidate.parents or not candidate.is_file() or _sha256(candidate) != expected:
            raise SupplyChainVerificationError("staged source does not match the signed source manifest")


def _trusted_signer(trust_policy_path: Path, provenance: Mapping[str, Any], key_id: object, *, allow_test_trust_policy: bool) -> Path:
    policy = _read_json(trust_policy_path)
    if policy.get("schema_version") != "oci.logan.splunk.function-supply-chain-trust-policy.v1":
        raise SupplyChainVerificationError("unsupported supply-chain trust policy")
    if policy.get("test_only") is True and not allow_test_trust_policy:
        raise SupplyChainVerificationError("test-only trust policy cannot authorize a pre-live release")
    signers = policy.get("trusted_signers")
    if not isinstance(signers, list):
        raise SupplyChainVerificationError("trust policy does not contain approved signers")
    signer = next((item for item in signers if isinstance(item, Mapping) and item.get("key_id") == key_id), None)
    if signer is None:
        raise SupplyChainVerificationError("provenance signer is not approved by the trust policy")
    builder = provenance.get("builder")
    if not isinstance(builder, Mapping) or builder.get("id") != signer.get("builder_id") or builder.get("workflow_identity") != signer.get("workflow_identity"):
        raise SupplyChainVerificationError("provenance builder or workflow identity is not approved")
    return _relative_receipt_path(trust_policy_path.resolve().parent, signer.get("public_key_path"), "trusted signer public key")


def _verify_provenance(
    *,
    base: Path,
    descriptor: object,
    trust_policy_path: Path,
    deployed_digest: str,
    source_hash: str,
    lock_hash: str,
    sbom_hash: str,
    scan_hashes: Mapping[str, str],
    image_signature_hash: str,
    allow_test_trust_policy: bool,
) -> str:
    if not isinstance(descriptor, Mapping):
        raise SupplyChainVerificationError("signed provenance descriptor is required")
    if descriptor.get("signature_algorithm") != "openssl-dgst-sha256-rsa":
        raise SupplyChainVerificationError("provenance must use the approved OpenSSL SHA-256 RSA signature format")
    provenance_path = _hashed_file(base, descriptor.get("path"), descriptor.get("sha256"), "provenance")
    signature_path = _hashed_file(base, descriptor.get("signature_path"), descriptor.get("signature_sha256"), "provenance signature")
    provenance = _read_json(provenance_path)
    if provenance.get("schema_version") != "oci.logan.splunk.function-build-provenance.v1":
        raise SupplyChainVerificationError("unsupported signed provenance schema")
    subject = provenance.get("subject")
    materials = provenance.get("materials")
    if not isinstance(subject, Mapping) or subject.get("image_digest") != deployed_digest:
        raise SupplyChainVerificationError("signed provenance does not identify the deployed image digest")
    if not isinstance(materials, Mapping) or materials.get("source_manifest_sha256") != source_hash or materials.get("dependency_lock_sha256") != lock_hash:
        raise SupplyChainVerificationError("signed provenance does not identify the verified source materials")
    if materials.get("sbom_sha256") != sbom_hash or materials.get("image_signature_receipt_sha256") != image_signature_hash:
        raise SupplyChainVerificationError("signed provenance does not identify the verified SBOM or image-signature receipt")
    signed_scans = materials.get("scan_receipt_sha256")
    if not isinstance(signed_scans, Mapping) or dict(signed_scans) != dict(scan_hashes):
        raise SupplyChainVerificationError("signed provenance does not identify the exact verified scan receipts")
    public_key = _trusted_signer(trust_policy_path, provenance, descriptor.get("key_id"), allow_test_trust_policy=allow_test_trust_policy)
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature_path), str(provenance_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SupplyChainVerificationError("signed provenance signature is invalid for the approved trust root")
    return _sha256(provenance_path)


def _requirements() -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw_line in FUNCTION_REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = PACKAGE_RE.fullmatch(line)
        if not match:
            raise SupplyChainVerificationError("canonical requirements are not exact package pins")
        pins[match.group(1).lower().replace("_", "-")] = match.group(2)
    if not pins:
        raise SupplyChainVerificationError("canonical requirements are empty")
    return pins


def _verify_lock(path: Path, descriptor: Mapping[str, Any]) -> str:
    text = path.read_text(encoding="utf-8")
    packages: dict[str, tuple[str, list[str]]] = {}
    chunks = re.split(r"(?m)^(?=[A-Za-z0-9_.-]+==)", text)
    for chunk in chunks:
        lines = [line.strip() for line in chunk.splitlines() if line.strip() and not line.strip().startswith("#")]
        if not lines:
            continue
        match = PACKAGE_RE.match(lines[0])
        if not match:
            raise SupplyChainVerificationError("dependency lock has an invalid package declaration")
        name = match.group(1).lower().replace("_", "-")
        hashes = HASH_RE.findall("\n".join(lines))
        if not hashes:
            raise SupplyChainVerificationError(f"dependency lock package {name} has no sha256 hash")
        packages[name] = (match.group(2), hashes)
    direct = _requirements()
    if not set(direct).issubset(packages):
        raise SupplyChainVerificationError("dependency lock omits a canonical direct dependency")
    if any(packages[name][0] != version for name, version in direct.items()):
        raise SupplyChainVerificationError("dependency lock direct pins differ from canonical requirements")
    if len(packages) <= len(direct):
        raise SupplyChainVerificationError("dependency lock has no declared transitive dependencies")
    direct_count = descriptor.get("direct_dependency_count")
    transitive_count = descriptor.get("transitive_dependency_count")
    if direct_count != len(direct) or not isinstance(transitive_count, int) or transitive_count != len(packages) - len(direct):
        raise SupplyChainVerificationError("dependency lock package counts do not match content")
    return _sha256(path)


def _tied_receipt(payload: Mapping[str, Any], *, image_digest: str, source_hash: str, lock_hash: str, label: str) -> None:
    if payload.get("image_digest") != image_digest:
        raise SupplyChainVerificationError(f"{label} does not identify the deployed image digest")
    if payload.get("source_manifest_sha256") != source_hash:
        raise SupplyChainVerificationError(f"{label} does not identify the source manifest")
    if payload.get("dependency_lock_sha256") != lock_hash:
        raise SupplyChainVerificationError(f"{label} does not identify the dependency lock")


def verify(
    attestation_path: Path,
    deployed_image_digest: str,
    trust_policy_path: Path,
    staged_build_context: Path,
    *,
    allow_test_trust_policy: bool = False,
) -> dict[str, object]:
    deployed_digest = _digest(deployed_image_digest, "deployed image digest")
    attestation = _read_json(attestation_path)
    if attestation.get("schema_version") != "oci.logan.splunk.function-supply-chain-attestation.v1":
        raise SupplyChainVerificationError("unsupported attestation schema")
    if attestation.get("receipt_type") != "external_pre_live_attestation" or attestation.get("evidence_class") != "externally_verified":
        raise SupplyChainVerificationError("attestation is not an externally verified pre-live receipt")
    if attestation.get("example") is not False:
        raise SupplyChainVerificationError("example or local-only receipts cannot authorize release")
    image = attestation.get("deployed_image")
    if not isinstance(image, Mapping) or _digest(image.get("digest"), "attestation image digest") != deployed_digest:
        raise SupplyChainVerificationError("attestation image digest differs from deployed image digest")

    base = attestation_path.resolve().parent
    source_path, source_manifest = _receipt_file(base, attestation.get("source_manifest"), "source manifest")
    if source_manifest.get("schema_version") != "oci.logan.splunk.function-build-context.v1":
        raise SupplyChainVerificationError("source manifest is not a populated staged Function manifest")
    _verify_staged_source(source_manifest, staged_build_context)
    source_hash = _sha256(source_path)
    lock_descriptor = attestation.get("dependency_lock")
    if not isinstance(lock_descriptor, Mapping):
        raise SupplyChainVerificationError("dependency lock descriptor is required")
    lock_path = _relative_receipt_path(base, lock_descriptor.get("path"), "dependency_lock.path")
    expected_lock_hash = _string(lock_descriptor.get("sha256"), "dependency_lock.sha256")
    if _sha256(lock_path) != expected_lock_hash:
        raise SupplyChainVerificationError("dependency lock content hash does not match")
    lock_hash = _verify_lock(lock_path, lock_descriptor)

    sbom_path, sbom = _receipt_file(base, attestation.get("sbom"), "SBOM")
    sbom_hash = _sha256(sbom_path)
    _tied_receipt(sbom, image_digest=deployed_digest, source_hash=source_hash, lock_hash=lock_hash, label="SBOM")
    scans = attestation.get("scans")
    if not isinstance(scans, list):
        raise SupplyChainVerificationError("scan receipts are required")
    scan_types: set[str] = set()
    scan_hashes: dict[str, str] = {}
    for scan in scans:
        if not isinstance(scan, Mapping):
            raise SupplyChainVerificationError("scan descriptor is invalid")
        scan_type = _string(scan.get("type"), "scan.type")
        if scan_type in scan_types:
            raise SupplyChainVerificationError("duplicate scan type")
        scan_types.add(scan_type)
        scan_path, scan_receipt = _receipt_file(base, scan, f"{scan_type} scan")
        scan_hashes[scan_type] = _sha256(scan_path)
        _tied_receipt(scan_receipt, image_digest=deployed_digest, source_hash=source_hash, lock_hash=lock_hash, label=f"{scan_type} scan")
        if scan_receipt.get("result") != "pass":
            raise SupplyChainVerificationError(f"{scan_type} scan is not passing")
    if scan_types != REQUIRED_SCAN_TYPES:
        raise SupplyChainVerificationError("exactly SCA, SAST, IaC, and container scan receipts are required")
    signature_path, signature = _receipt_file(base, attestation.get("signature"), "signature")
    image_signature_hash = _sha256(signature_path)
    _tied_receipt(signature, image_digest=deployed_digest, source_hash=source_hash, lock_hash=lock_hash, label="signature")
    if signature.get("verified") is not True or signature.get("subject_digest") != deployed_digest:
        raise SupplyChainVerificationError("signature does not verify the deployed image digest")
    provenance_hash = _verify_provenance(
        base=base,
        descriptor=attestation.get("provenance"),
        trust_policy_path=trust_policy_path,
        deployed_digest=deployed_digest,
        source_hash=source_hash,
        lock_hash=lock_hash,
        sbom_hash=sbom_hash,
        scan_hashes=scan_hashes,
        image_signature_hash=image_signature_hash,
        allow_test_trust_policy=allow_test_trust_policy,
    )
    return {
        "schema_version": "oci.logan.splunk.function-supply-chain-verification.v1",
        "status": "accepted_for_pre_live_gate",
        "evidence_class": "externally_verified",
        "provider_validation": "not_run",
        "provider_verified": False,
        "external_calls": [],
        "deployed_image_digest": deployed_digest,
        "attestation_sha256": _sha256(attestation_path),
        "provenance_sha256": provenance_hash,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation", required=True, type=Path)
    parser.add_argument("--deployed-image-digest", required=True)
    parser.add_argument("--trust-policy", required=True, type=Path, help="Approved signer trust policy, retained outside this repository")
    parser.add_argument("--staged-build-context", required=True, type=Path, help="Exact staged Function context used to build the image")
    parser.add_argument("--allow-test-trust-policy", action="store_true", help="Allow an explicitly test-only trust policy for offline tests only")
    parser.add_argument("--terraform-tfvars-out", type=Path, help="Write an atomic JSON tfvars binding for the verified image and receipts")
    arguments = parser.parse_args(argv)
    try:
        receipt = verify(arguments.attestation, arguments.deployed_image_digest, arguments.trust_policy, arguments.staged_build_context, allow_test_trust_policy=arguments.allow_test_trust_policy)
        receipt["terraform_binding"] = {
            "splunk_evidence_exporter_function_image_digest": receipt["deployed_image_digest"],
            "splunk_evidence_exporter_function_attestation_sha256": receipt["attestation_sha256"],
            "splunk_evidence_exporter_function_provenance_sha256": receipt["provenance_sha256"],
            "splunk_evidence_exporter_function_attestation_path": str(arguments.attestation.resolve()),
            "splunk_evidence_exporter_function_provenance_path": str((arguments.attestation.resolve().parent / _string(_read_json(arguments.attestation).get("provenance", {}).get("path"), "provenance.path")).resolve()),
        }
        if arguments.terraform_tfvars_out:
            target = arguments.terraform_tfvars_out.resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile("w", dir=target.parent, encoding="utf-8", delete=False) as handle:
                json.dump(receipt["terraform_binding"], handle, indent=2, sort_keys=True)
                handle.write("\n")
                temporary = Path(handle.name)
            temporary.replace(target)
    except (OSError, SupplyChainVerificationError, UnicodeDecodeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "rejected", "error_type": "SupplyChainVerificationError"}, sort_keys=True))
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
