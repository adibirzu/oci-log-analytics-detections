"""Exercise SBOM regeneration and drift detection through the offline CLI."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = Path("generated/security/oci-log-analytics-detections.cdx.json")
INPUTS = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-hunting-test.txt",
    "requirements-mcp.txt",
    "stack/modules/splunk_evidence_exporter/function/requirements.txt",
    "webapp/pnpm-lock.yaml",
)


def test_sbom_regeneration_and_freshness(tmp_path):
    for name in (*INPUTS, "scripts/generate_sbom.py"):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)

    def run(mode, hash_seed, root=tmp_path):
        return subprocess.run(
            [sys.executable, "-X", "utf8", str(root / "scripts/generate_sbom.py"), mode],
            cwd=tmp_path.parent,
            env={"PYTHONHASHSEED": str(hash_seed)},
            capture_output=True,
            check=False,
            text=True,
            timeout=15,
        )

    artifact = tmp_path / ARTIFACT
    assert run("--check", 1).returncode == 1
    assert not artifact.exists()
    result = run("--write", 1)
    assert result.returncode == 0, result.stderr
    first = artifact.read_bytes()
    assert run("--write", 2).returncode == 0
    assert artifact.read_bytes() == first == (ROOT / ARTIFACT).read_bytes()
    assert run("--check", 2, ROOT).returncode == 0
    assert run("--check", 3).returncode == 0

    bom = json.loads(first)
    assert (bom["bomFormat"], bom["specVersion"]) == ("CycloneDX", "1.6")
    assert bom["metadata"]["component"]["name"] == "oci-log-analytics-detections"
    components = {item["purl"]: item for item in bom["components"]}
    assert len(components) == len(bom["components"])
    assert any(purl.startswith("pkg:npm/next@") for purl in components)
    assert any(purl.startswith("pkg:npm/%40eslint-community/regexpp@") for purl in components)
    assert any(purl.startswith("pkg:pypi/oci@") for purl in components)
    assert "version" not in components["pkg:pypi/oci"]
    assert bom["compositions"][0]["aggregate"] == "incomplete"

    requirements = tmp_path / "requirements.txt"
    with requirements.open("a", encoding="utf-8") as stream:
        stream.write("example-dependency==1.2.3\n")
    result = run("--check", 4)
    assert result.returncode == 1
    assert "out of date" in result.stderr
    assert artifact.read_bytes() == first
    assert run("--write", 5).returncode == 0
    assert any(item["purl"] == "pkg:pypi/example-dependency@1.2.3"
               for item in json.loads(artifact.read_bytes())["components"])
    assert run("--check", 6).returncode == 0
