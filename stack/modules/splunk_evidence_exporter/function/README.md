# Splunk evidence exporter Function build context

Terraform consumes an operator-built OCI Registry image. This directory does not duplicate the exporter package or canonical detection artifacts. From the repository root, stage an isolated build context with:

```bash
python3 stack/modules/splunk_evidence_exporter/function/stage_build_context.py --output /tmp/splunk-evidence-exporter-build-context
```

The command copies the existing `scripts/splunk_evidence_exporter/` package, its thin `func.py` entrypoint, the detection registry and referenced canonical queries, delivery configuration, and evidence schema. It writes `build-context-manifest.json` with a SHA-256 digest for every staged input and fails closed if the target is non-empty or a referenced artifact is missing/outside `queries/`.

Inspect the manifest and context before any separately authorized image build. A later, approved operator action can run `fn build` from the staged directory, then scan/sign/push the image and pin its reference and digest in Terraform. This repository task does not build, push, or access a registry.
# Production supply-chain gate

`func.yaml` is only local build metadata and is not a production provenance
record. Production enablement requires an externally built, scanned and signed
OCI Registry image addressed by a non-empty `sha256:` digest. Retain the SCA,
SAST, IaC scan, container scan and SBOM receipts with the reviewed digest; this
repository intentionally performs none of those networked build actions.
