"""Exercise the built Pages artifact against the reviewed OCI content inventory."""

import hashlib
import ipaddress
import json
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts/build_detection_explorer.py"
VENDORS = {"elastic": "elastic/detection-rules", "splunk": "splunk/security_content"}


def build(output):
    result = subprocess.run(
        [sys.executable, str(BUILDER), "--output", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.fixture(scope="module")
def export(tmp_path_factory):
    output = tmp_path_factory.mktemp("explorer")
    build(output)
    return output


def test_exact_query_parity_and_inventory(export):
    manifest = json.loads((ROOT / "queries/content_manifest.json").read_text())
    families = json.loads((ROOT / "config/cross_siem_detection_catalog.json").read_text())
    companion_paths = {
        f"queries/{path}"
        for family in families["detection_families"]
        for path in family["logan_queries"]
    }
    expected = {
        item["path"]: item
        for item in manifest["queries"]
        if item["surface"] in {"base", "sentinel", "apps"} or item["path"] in companion_paths
    }
    catalog = json.loads((export / "catalog.json").read_text())
    records = {item["id"]: item for item in catalog["rules"]}
    assert len(records) == len(catalog["rules"])
    assert records.keys() == expected.keys()
    assert catalog["contentDigest"] == manifest["content_digest"]
    native_hunt = records["queries/hunting/oci_resource_deletion_wave.json"]
    assert native_hunt["platform"] == "oci"
    assert {mapping["status"] for mapping in native_hunt["mappings"].values()} == {"oci-specific"}
    for path, item in expected.items():
        raw = (ROOT / path).read_bytes()
        source = json.loads(raw)
        rule = records[path]
        assert rule["query"] == source["query"], path
        assert rule["title"] == source["title"], path
        assert rule["description"] == source.get("description", ""), path
        assert rule["provenance"]["sha256"] == hashlib.sha256(raw).hexdigest() == item["sha256"]
        assert (rule["kind"] == "hunting") == (path in companion_paths)
        assert {"severity", "platform", "category", "sources", "tactics", "techniques"} <= rule.keys()


def test_verified_mappings_and_hunt_families(export):
    catalog = json.loads((export / "catalog.json").read_text())
    families = json.loads((ROOT / "config/cross_siem_detection_catalog.json").read_text())
    records = {item["id"]: item for item in catalog["rules"]}
    for family in families["detection_families"]:
        for path in family["logan_queries"]:
            assert family["title"] in records[f"queries/{path}"]["families"]

    for vendor, repository in VENDORS.items():
        index = catalog["upstreams"][vendor]
        assert index
        for upstream_id, reference in index.items():
            assert str(upstream_id) == reference["id"]
            assert re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", upstream_id)
            assert re.fullmatch(r"[a-f0-9]{40}", reference["revision"])
            assert re.fullmatch(r"[a-f0-9]{64}", reference["sha256"])
            assert reference["title"]
            assert reference["url"] == (
                f"https://github.com/{repository}/blob/{reference['revision']}/{reference['path']}"
            )
            assert reference["path"].startswith("rules/" if vendor == "elastic" else "detections/")
            assert reference["path"].endswith(".toml" if vendor == "elastic" else ".yml")
        linked = set()
        for rule in records.values():
            mapping = rule["mappings"][vendor]
            assert mapping["status"] in {"exact", "related", "unmapped", "oci-specific"}
            assert bool(mapping["references"]) == (mapping["status"] in {"exact", "related"})
            for link in mapping["references"]:
                assert link["confidence"] in {"exact", "related"}
                assert link["rationale"].strip()
                assert link["id"] in index
                linked.add(link["id"])
        assert linked == index.keys()


class AssetLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        for name in ("href", "src"):
            if name in attributes:
                self.paths.append(attributes[name])


def test_export_is_deterministic_portable_and_tenant_neutral(export, tmp_path):
    other = tmp_path / "second"
    build(other)
    files = {file.name: file.read_bytes() for file in export.iterdir() if file.is_file()}
    assert files.keys() == {"index.html", "explorer.css", "explorer.js", "catalog.json"}
    assert files == {file.name: file.read_bytes() for file in other.iterdir() if file.is_file()}
    links = AssetLinks()
    links.feed(files["index.html"].decode())
    for url in links.paths:
        parsed = urlsplit(url)
        if not parsed.scheme and parsed.path:
            assert not parsed.path.startswith("/")
            assert (export / parsed.path).is_file(), url

    body = b"\n".join(files.values()).decode()
    assert not re.search(r"\bocid1\.", body, flags=re.IGNORECASE)
    private_networks = tuple(
        ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    )
    for address in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", body):
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        assert not any(parsed in network for network in private_networks)


def test_pages_forge_catalog_preserves_safe_records_and_omits_private_hunts(tmp_path):
    source_path = ROOT / "queries/forge_detection_catalog.json"
    source_bytes = source_path.read_bytes()
    pages_forge = tmp_path / "forge.json"
    result = subprocess.run(
        [sys.executable, str(BUILDER), "--output", str(tmp_path / "explorer"),
         "--forge-catalog-output", str(pages_forge)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    published = json.loads(pages_forge.read_bytes())
    omitted = {
        "hunting/web_to_cloud_attack_path_link",
        "hunting/web_to_cloud_attack_timeline",
        "hunting/web_to_cloud_compromised_machines",
        "hunting/web_to_cloud_mitre_sunburst",
        "hunting/web_to_cloud_vcn_egress",
    }
    assert published["items"] == [item for item in json.loads(source_bytes)["items"] if item["id"] not in omitted]
    assert published["total_items"] == len(published["items"]) == sum(published["surface_counts"].values())
    assert source_path.read_bytes() == source_bytes
