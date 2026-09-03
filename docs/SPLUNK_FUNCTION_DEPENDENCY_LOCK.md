# Splunk evidence exporter dependency lock and pre-live attestation

`stack/modules/splunk_evidence_exporter/function/requirements.txt` is the
canonical direct dependency input for the Function build:

```text
fdk==0.1.90
oci==2.160.3
```

It deliberately is **not** a production lock: a direct-pin file cannot prove
the selected transitive dependency graph or artifact contents. This repository
does not invent package hashes or check in a fake accepted receipt. An approved
external builder must resolve the exact direct pins into a retained,
hash-locked `requirements-hashed.lock` that lists the direct **and transitive**
packages, pins every package, and supplies at least one SHA-256 hash per
package. It must install that lock with:

```bash
python -m pip install --require-hashes -r requirements-hashed.lock
```

The lock belongs beside the build receipts, outside this repository unless an
approved release process stores it in a protected evidence location. Never
replace a package hash after image approval. Any direct-pin, hash, source, or
image-digest change starts a new build and review.

## Required receipt bundle

Before enabling the exporter Function, the release owner assembles one private
directory containing these externally produced artifacts:

| Receipt | Required binding |
|---|---|
| `build-context-manifest.json` | SHA-256 recorded in the attestation; schema `oci.logan.splunk.function-build-context.v1` |
| `requirements-hashed.lock` | exact pins, hashes, all transitive dependencies; SHA-256 and direct/transitive counts recorded |
| SBOM | source-manifest SHA-256, lock SHA-256, and immutable image digest |
| SCA, SAST, IaC, and container scan receipts | each passing and each bound to the same source-manifest SHA-256, lock SHA-256, and image digest |
| Signature verification receipt | verified signature whose subject is the same immutable image digest |
| Signed provenance statement and detached signature | SHA-256 of each file, exact image digest, source-manifest and lock material hashes, and the approved builder/workflow identity |
| Approved trust policy | retained public trust root, approved signer key ID, and exact expected builder/workflow identity |
| Attestation JSON | file hashes for all of the above plus the reviewed deployed image reference/digest |

The attestation's `receipt_type` must be `external_pre_live_attestation`, its
`evidence_class` must be `externally_verified`, and `example` must be `false`.
The signed provenance format is
`oci.logan.splunk.function-build-provenance.v1`; it is detached-signed with
`openssl dgst -sha256` using an approved RSA public key in the trust policy.
The verifier checks the signer against that trust root, then checks the exact
builder ID and workflow identity. The signed provenance must carry the SHA-256
of the SBOM, a complete typed map of the four SCA/SAST/IaC/container receipt
hashes, and the image-signature-verification receipt hash. It also recalculates
every file hash in the staged build context against `build-context-manifest.json`,
and cross-binds the manifest, lock, SBOM, scans, provenance, attestation, and
immutable image.

The verifier rejects local examples, test-only trust policies (unless the
explicit offline test override is supplied), absent receipts, forged/wrong
signers, unexpected builder/workflow identities, path traversal, stale staged
sources, mutable image references, a lock without transitive packages, an
unhashed package, non-passing scans, or any mismatch. It performs no network
calls and does not turn a receipt into provider or customer acceptance.

Run the machine-verifiable pre-live gate using the exact reviewed Function
image digest:

```bash
python3 scripts/verify_splunk_function_supply_chain.py \
  --attestation <PRIVATE_RECEIPT_DIRECTORY>/attestation.json \
  --trust-policy <PRIVATE_RECEIPT_DIRECTORY>/approved-trust-policy.json \
  --staged-build-context <PRIVATE_STAGED_FUNCTION_CONTEXT> \
  --deployed-image-digest sha256:<64-lowercase-hex-characters>
```

Expected success is `accepted_for_pre_live_gate`,
`provider_validation: not_run`, and `external_calls: []`. A nonzero exit is a
release blocker. This gate verifies receipt integrity and cross-binding only;
the separately authorized OCI Registry/Function deployment, disabled alarm
canary, HEC delivery, and Splunk search validation remain required.

`func.yaml` build/run images are mutable local-build metadata only. Terraform
production enablement requires an immutable OCI Registry digest and must use
the same digest accepted by this gate. Have the verifier create the exact
private tfvars binding instead of copying receipt hashes by hand:

```bash
python3 scripts/release_checklist.py --splunk-pre-live-supply-chain-gate \
  --splunk-attestation <PRIVATE_RECEIPT_DIRECTORY>/attestation.json \
  --splunk-trust-policy <PRIVATE_RECEIPT_DIRECTORY>/approved-trust-policy.json \
  --splunk-staged-build-context <PRIVATE_STAGED_FUNCTION_CONTEXT> \
  --splunk-image-digest sha256:<64-lowercase-hex-characters> \
  --splunk-terraform-tfvars-out <PRIVATE_DIRECTORY>/supply-chain.auto.tfvars.json
```

The emitted private JSON contains the exact image digest, private attestation
and provenance paths, plus
`splunk_evidence_exporter_function_attestation_sha256` and
`splunk_evidence_exporter_function_provenance_sha256`. Terraform refuses an
enabled exporter unless both receipt files are present and their recomputed
hashes match the verified binding; it stores only the receipt hashes in Function
configuration for operational traceability. The pre-live command is local-only
and does not apply Terraform, access OCI, or contact Splunk.
