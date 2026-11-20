#!/usr/bin/env python3
"""Generate a CycloneDX 1.6 inventory from the repository's local dependency inputs."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "generated/security/oci-log-analytics-detections.cdx.json"
PROJECT = "oci-log-analytics-detections"
LOCKFILE = "webapp/pnpm-lock.yaml"
REQUIREMENTS = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-hunting-test.txt",
    "requirements-mcp.txt",
    "stack/modules/splunk_evidence_exporter/function/requirements.txt",
)
REQUIREMENT = re.compile(r"([a-zA-Z0-9][a-zA-Z0-9_.-]*)(.*)")
SPECIFIERS = r"(?:===|==|~=|!=|<=|>=|<|>)[a-zA-Z0-9.*+!_-]+"
SOURCE = PROJECT + ":source"
DECLARATION = PROJECT + ":requirement"


def build_sbom():
    inputs = {name: (ROOT / name).read_bytes() for name in (*REQUIREMENTS, LOCKFILE)}
    components = {}

    def add(ecosystem, name, version, source, declaration=None):
        purl = f"pkg:{ecosystem}/{quote(name, safe='/')}"
        if version:
            purl += f"@{quote(version, safe='')}"
        item = components.setdefault(
            purl,
            {"type": "library", "bom-ref": purl, "name": name, "purl": purl, "properties": []},
        )
        if version:
            item["version"] = version
        properties = [{"name": SOURCE, "value": source}]
        if declaration:
            properties.append({"name": DECLARATION, "value": f"{source}: {declaration}"})
        for prop in properties:
            if prop not in item["properties"]:
                item["properties"].append(prop)

    for source in REQUIREMENTS:
        for line in inputs[source].decode("utf-8").splitlines():
            line = line.partition("#")[0].strip()
            if not line:
                continue
            if line.startswith("-r "):
                if (Path(source).parent / line[3:].strip()).as_posix() not in REQUIREMENTS:
                    raise ValueError(f"Untracked requirements include in {source}")
                continue

            match = REQUIREMENT.fullmatch(line)
            if not match:
                raise ValueError(f"Unsupported dependency declaration in {source}")
            name, constraint = match.groups()
            constraint = constraint.strip()
            if constraint and not re.fullmatch(fr"{SPECIFIERS}(?:\s*,\s*{SPECIFIERS})*", constraint):
                raise ValueError(f"Unsupported dependency declaration in {source}")
            exact = re.fullmatch(r"==([a-zA-Z0-9.+!_-]+)", constraint)
            add("pypi", re.sub(r"[-_.]+", "-", name).lower(),
                exact[1] if exact else None, source, line)

    lock = yaml.safe_load(inputs[LOCKFILE])
    if lock["lockfileVersion"] != "9.0" or not isinstance(lock["packages"], dict):
        raise ValueError("Expected pnpm lockfile version 9 with a package inventory")
    for entry in sorted(lock["packages"]):
        name, separator, version = entry.rpartition("@")
        if not separator or not re.fullmatch(r"(?:@[\w.-]+/)?[\w.-]+", name) or not re.fullmatch(r"[0-9][\w.+-]*", version):
            raise ValueError("Unsupported pnpm package identifier")
        add("npm", name, version, LOCKFILE)

    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": PROJECT,
                "name": PROJECT,
                "description": (
                    "Repository dependency inventory from Python requirements and the webapp "
                    "pnpm lockfile. Python transitives, infrastructure, and built images are outside this inventory."
                ),
            },
            "properties": [
                {"name": f"{PROJECT}:sha256:{name}", "value": hashlib.sha256(data).hexdigest()}
                for name, data in sorted(inputs.items())
            ],
        },
        "components": [components[key] for key in sorted(components)],
        "compositions": [{"aggregate": "incomplete", "assemblies": [PROJECT]}],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        data = (json.dumps(build_sbom(), indent=2, sort_keys=True) + "\n").encode("utf-8")
        if args.write:
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT.write_bytes(data)
        elif not OUTPUT.is_file() or OUTPUT.read_bytes() != data:
            print("SBOM missing or out of date. Run python scripts/generate_sbom.py --write.", file=sys.stderr)
            return 1
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as error:
        print(f"SBOM generation failed: {error}", file=sys.stderr)
        return 1
    print(f"SBOM {'generated' if args.write else 'verified'}: {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
