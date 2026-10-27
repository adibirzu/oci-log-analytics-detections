#!/usr/bin/env python3
"""Generate reviewed LOCAL legacy bindings from fixed public Git objects only."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

try:
    from .parser_contract import ContractError, contract_hash, parser_contract, require_additive, identity_hash
except ImportError:
    from parser_contract import ContractError, contract_hash, parser_contract, require_additive, identity_hash

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL = "94809dcb20b872728785458c88aad794869da7f6"
REVIEWED = "f44ee1be0b16a0caa9f79f14b7c615f8f10c30bd"
OUTPUT = ROOT / "config/sentinel_legacy_compatibility_v1.json"
DICTIONARY = "queries/log_source_field_dictionary.json"
REPORT = "queries/sentinel_conversion_report.json"


def git(root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    try:
        run = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", str(root), *args], env=env, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        raise ContractError("Historical Git object unavailable") from None
    if run.returncode or len(run.stdout) > 64 * 1024 * 1024:
        raise ContractError("Historical Git object unavailable")
    return run.stdout


def corpus(root, ref):
    data = git(root, "archive", "--format=tar", ref, "queries/sentinel")
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            if member.isdir():
                continue
            if not member.isfile() or not member.name.startswith("queries/sentinel/") or not member.name.endswith(".json") or Path(member.name).name != member.name.removeprefix("queries/sentinel/") or member.size > 1024 * 1024:
                raise ContractError("Invalid historical corpus")
            result[member.name] = archive.extractfile(member).read()
    return result


def blob_identity(data):
    # Both fixed public source commits use Git's SHA-1 object format.
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def source_blobs(root, ref):
    result = {}
    for row in git(root, "ls-tree", "-r", "-z", ref, "queries/sentinel").split(b"\0"):
        if not row:
            continue
        metadata, path = row.split(b"\t", 1)
        mode, kind, blob = metadata.split()
        if mode not in {b"100644", b"100755"} or kind != b"blob":
            raise ContractError("Invalid historical corpus")
        result[path.decode()] = blob.decode()
    return result


def raw_schema(dictionary):
    return contract_hash({k: v for k, v in dictionary.items() if k != "generated_at"})


def generate(root=ROOT):
    old_raw = git(root, "show", f"{HISTORICAL}:{DICTIONARY}")
    new_raw = git(root, "show", f"{REVIEWED}:{DICTIONARY}")
    report_raw = git(root, "show", f"{HISTORICAL}:{REPORT}")
    current_report = git(root, "show", f"{REVIEWED}:{REPORT}")
    if current_report != report_raw:
        raise ContractError("Historical report changed")
    old_dictionary, new_dictionary = json.loads(old_raw), json.loads(new_raw)
    old_contract, new_contract = parser_contract(old_dictionary), parser_contract(new_dictionary)
    require_additive(old_contract, new_contract)
    report = json.loads(report_raw)
    rows = [row for row in report["attempted"] if row.get("output_file")]
    by_output = {row["output_file"]: row for row in rows}
    before, after = corpus(root, HISTORICAL), corpus(root, REVIEWED)
    old_blobs, new_blobs = source_blobs(root, HISTORICAL), source_blobs(root, REVIEWED)
    if len(before) != 590 or set(before) != set(after) or len(rows) != len(by_output) or len(rows) != len(before):
        raise ContractError("Historical corpus binding mismatch")
    old_hash = raw_schema(old_dictionary)
    bindings = []
    observed = set()
    for path in sorted(before):
        if blob_identity(before[path]) != old_blobs.get(path) or blob_identity(after[path]) != new_blobs.get(path):
            raise ContractError("Historical archive differs from Git source blobs")
        original, current = json.loads(before[path]), json.loads(after[path])
        output = path.removeprefix("queries/")
        row = by_output.get(output, {})
        if original.get("live_validation_status") != "passed" or row.get("live_validation_status") != "passed" or original.get("conversion_status") != "promoted" or original.get("parser_schema_hash") != old_hash or row.get("sentinel_id") != original.get("sentinel_id") or row.get("source_path") != original.get("sentinel_source_path"):
            raise ContractError("Historical acceptance binding mismatch")
        if {k: v for k, v in original.items() if k != "parser_schema_hash"} != {k: v for k, v in current.items() if k != "parser_schema_hash"}:
            raise ContractError("Historical query metadata changed")
        observed.add(current.get("parser_schema_hash"))
        # Whitelisted identifiers and hashes only. Never copy query/report text.
        bindings.append({"output_file": output, "historical_blob": old_blobs[path], "reviewed_blob": new_blobs[path], "reviewed_file_sha256": hashlib.sha256(after[path]).hexdigest(), "query_sha256": hashlib.sha256(current["query"].encode()).hexdigest(), "identity_sha256": identity_hash(current), "historical_report_row_sha256": contract_hash(row)})
    if len(observed) != 1 or not all(isinstance(v, str) and len(v) == 64 for v in observed):
        raise ContractError("Unclassified legacy hash")
    return {"schema_version": "forge.sentinel-legacy-compatibility.v1", "evidence_class": "code-backed-local-source-binding", "provider_revalidated": False, "historical_commit": HISTORICAL, "reviewed_commit": REVIEWED, "historical_report_blob": git(root, "rev-parse", f"{HISTORICAL}:{REPORT}").decode().strip(), "historical_dictionary_blob": git(root, "rev-parse", f"{HISTORICAL}:{DICTIONARY}").decode().strip(), "historical_raw_schema_sha256": old_hash, "observed_legacy_raw_schema_sha256": observed.pop(), "legacy_raw_hash_status": "unresolved_preserved", "historical_parser_contract": old_contract, "reviewed_parser_contract_sha256": contract_hash(new_contract), "reviewed_report_sha256": hashlib.sha256(current_report).hexdigest(), "bindings": bindings}


def encoded(manifest):
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        data = encoded(generate())
        if args.write:
            OUTPUT.write_bytes(data)
        elif OUTPUT.read_bytes() != data:
            raise ContractError("Legacy manifest differs from fixed source provenance")
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        print("Legacy compatibility generation failed; fixed source binding unavailable", file=__import__("sys").stderr)
        return 1
    print(json.dumps({"status": "generated" if args.write else "verified", "evidence_class": "code-backed-local-source-binding", "provider_revalidated": False, "manifest_sha256": hashlib.sha256(data).hexdigest()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
