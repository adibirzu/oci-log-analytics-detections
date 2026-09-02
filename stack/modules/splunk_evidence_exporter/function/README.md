# Splunk evidence exporter Function build context

Terraform consumes an operator-built OCI Registry image. This directory does not duplicate the exporter package or canonical detection artifacts. From the repository root, stage an isolated build context with:

```bash
python3 stack/modules/splunk_evidence_exporter/function/stage_build_context.py --output /tmp/splunk-evidence-exporter-build-context
```

The command copies the existing `scripts/splunk_evidence_exporter/` package, its thin `func.py` entrypoint, the detection registry and referenced canonical queries, delivery configuration, and evidence schema. It writes `build-context-manifest.json` with a SHA-256 digest for every staged input and fails closed if the target is non-empty or a referenced artifact is missing/outside `queries/`.

Inspect the manifest and context before any separately authorized image build. A later, approved operator action can run `fn build` from the staged directory, then scan/sign/push the image and pin its reference and digest in Terraform. This repository task does not build, push, or access a registry.
# Production supply-chain gate

`func.yaml` is only local build metadata and is not a production provenance
record. Its mutable `build_image` and `run_image` values are therefore local
development hints, never production image references. Terraform production
enablement requires an externally built, scanned and signed OCI Registry image
addressed by a non-empty `sha256:` digest.

The exact dependency and attestation contract is in
[`docs/SPLUNK_FUNCTION_DEPENDENCY_LOCK.md`](../../../../docs/SPLUNK_FUNCTION_DEPENDENCY_LOCK.md).
A production builder must resolve direct and transitive pins with
`pip install --require-hashes` using externally verified wheel or sdist
hashes. The repository does not invent or bless artifact hashes offline: the
machine-verifiable pre-live gate rejects a receipt unless the source manifest,
verified dependency lock, SBOM, passing SCA/SAST/IaC/container scans, signature,
and immutable deployed image digest all identify the same build. Retain that
private receipt bundle with the reviewed digest; this repository intentionally
performs none of those networked build actions.
