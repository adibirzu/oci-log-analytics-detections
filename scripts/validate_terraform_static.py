#!/usr/bin/env python3
"""Validate the optional Terraform stack without loading a provider.

The release stage must work from a clean checkout with no ``.terraform``
directory, plugin cache, credentials, or registry access.  This validator is
intentionally a small text contract check; it does not claim to replace
provider-backed ``terraform validate`` for an authorized deployment review.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STACK = ROOT / "stack"


def validate(root: Path = ROOT) -> list[str]:
    stack = root / "stack"
    errors: list[str] = []
    required = [
        stack / "main.tf",
        stack / "variables.tf",
        stack / "outputs.tf",
        stack / "schema.yaml",
        stack / "modules/splunk_evidence_exporter/main.tf",
        stack / "modules/splunk_evidence_exporter/variables.tf",
        stack / "modules/splunk_evidence_exporter/outputs.tf",
    ]
    for path in required:
        if not path.is_file():
            errors.append(f"missing required Terraform contract file: {path.relative_to(root)}")
    if errors:
        return errors
    root_text = (stack / "main.tf").read_text(encoding="utf-8")
    module = (stack / "modules/splunk_evidence_exporter/main.tf").read_text(encoding="utf-8")
    schema = (stack / "schema.yaml").read_text(encoding="utf-8")
    contracts = (
        ("oracle/oci provider source", r'source\s*=\s*"oracle/oci"', module),
        ("opt-in root module", r'enable_splunk_evidence_exporter\s*=\s*var\.enable_splunk_evidence_exporter', root_text),
        ("function resource", r'resource\s+"oci_functions_function"', module),
        ("vault secret reference", r'var\.splunk_hec_secret_id', module),
        ("disabled schema default", r'enable_splunk_evidence_exporter:\s*.*?default:\s*false', schema),
    )
    for label, pattern, text in contracts:
        if not re.search(pattern, text, re.DOTALL):
            errors.append(f"missing Terraform contract: {label}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", help="repository root to validate (used by clean-checkout tests)")
    parser.add_argument("--check-format", action="store_true", help="also enforce basic stable HCL formatting")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else ROOT
    errors = validate(root)
    if args.check_format:
        for path in sorted((root / "stack").rglob("*.tf")):
            text = path.read_text(encoding="utf-8")
            if not text.endswith("\n"):
                errors.append(f"Terraform file lacks final newline: {path.relative_to(root)}")
            if "\t" in text:
                errors.append(f"Terraform file contains tabs: {path.relative_to(root)}")
    if errors:
        for error in errors:
            print(f"[error] {error}")
        return 1
    print("static Terraform contracts and format checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
