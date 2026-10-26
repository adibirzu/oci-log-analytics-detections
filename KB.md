# oci-log-analytics-detections knowledge base

Troubleshooting reference. Read it only when an error occurs, not at session start.
Cross-cutting OCI, OKE, IAM and networking issues live in the shared OCI-DEMO KB: `~/dev/OCI-DEMO/KB.md`
(search it with `python3.11 ~/dev/OCI-DEMO/scripts/knowledge_lookup.py --query '<error>'`).

Add an entry after every error that needed investigation and a fix. Use the next number.

## Entry format

```
## KB-NNN: <component> - <short symptom>
- Error: <exact message>
- Root cause: <what was actually wrong>
- Fix: <what changed, with file/command>
- Prevention: <how to avoid it next time>
```

## KB-001: ORM package entrypoints did not match extracted paths
- Error: Extracted Terraform provisioners could not locate sibling deployment scripts, and Git-free Forge runtime staging omitted required package inputs.
- Root cause: Provisioners used stack-local script paths while the builder retained separate stack/scripts roots; ZIP metadata depended on source timestamps and exported trees lacked a verified source inventory.
- Fix: Align working-directory paths, validate executable/assets closure, build deterministic archives atomically and stage hash-bound selected bytes through the owning generator. See [package source inventory and executable closure](docs/DEPLOYMENT.md#package-source-inventory-and-executable-closure).
- Prevention: Exercise actual extracted entrypoints and Git-free staging with synthetic provider boundaries; retain missing/tampered source, path/output safety and private JSON Terraform-variable refusal cases. Failed archive scan diagnostics require factual triage, not scanner weakening or automatic release acceptance.
