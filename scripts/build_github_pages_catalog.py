#!/usr/bin/env python3.11
"""Rebuild the OCI Log Analytics Detections catalogs, hunting bundle, and static GitHub Pages export."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
WEBAPP_DIR = PROJECT_ROOT / "webapp"


def _run(cmd: list[str], cwd: Path = PROJECT_ROOT) -> None:
    print(f"==> Running: {' '.join(cmd)} (cwd={cwd})")
    res = subprocess.run(cmd, cwd=cwd, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {' '.join(cmd)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-next-build",
        action="store_true",
        help="Only regenerate JSON/MD catalogs and copy forge_detection_catalog.json to docs/pages without running next build",
    )
    args = parser.parse_args()

    py = sys.executable
    _run([py, str(SCRIPTS_DIR / "field_dictionary.py"), "--validate-query-fields"])
    _run([py, str(SCRIPTS_DIR / "generate_catalog.py")])
    _run([py, str(SCRIPTS_DIR / "deploy_dashboard.py"), "--export-inventory"])
    _run([py, str(SCRIPTS_DIR / "generate_hunting_bundle.py")])
    _run([py, str(SCRIPTS_DIR / "generate_hunting_bundle.py"), "--check"])
    _run([py, str(SCRIPTS_DIR / "generate_logan_workbench_artifacts.py")])

    stage_script = WEBAPP_DIR / "deploy" / "oke" / "stage-detections-runtime.sh"
    if stage_script.is_file():
        _run(["bash", str(stage_script)], cwd=WEBAPP_DIR)

    if not args.skip_next_build:
        _run(["node", "scripts/build-github-pages.mjs"], cwd=WEBAPP_DIR)
    else:
        docs_pages = PROJECT_ROOT / "docs" / "pages"
        docs_pages.mkdir(parents=True, exist_ok=True)
        src = PROJECT_ROOT / "queries" / "forge_detection_catalog.json"
        dst = docs_pages / "forge_detection_catalog.json"
        dst.write_bytes(src.read_bytes())

    print("Successfully rebuilt GitHub Pages catalog and detection artifacts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
