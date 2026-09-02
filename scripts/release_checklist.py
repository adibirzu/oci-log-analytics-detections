#!/usr/bin/env python3
"""Run the local release checklist for the OCI Log Analytics detection engine.

The default mode performs only local/offline or dry-run gates. Live
``<OCI_PROFILE>`` checks are explicit via ``--include-live`` and do not mutate
OCI resources.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_DIR / "scripts"
HEALTH_DIR = PROJECT_DIR / "docs" / "health"
SENTINEL_BACKLOG_PRIORITY_PATH = PROJECT_DIR / "queries" / "sentinel_backlog_priority.json"
SPLUNK_EXPORTER_CLI = SCRIPTS_DIR / "splunk_evidence_exporter_cli.py"
TERRAFORM_STATIC_VALIDATOR = SCRIPTS_DIR / "validate_terraform_static.py"

OCID_RE = re.compile(r"\bocid1\.[A-Za-z0-9][A-Za-z0-9._-]{8,}\b", re.IGNORECASE)
REQUEST_ID_RE = re.compile(r"(?i)(opc[-_]request[-_]id\s*[:=]\s*)[A-Za-z0-9._:-]{12,}")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
IPV4_RE = re.compile(
    r"(?<![\d.])"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
    r"(?![\d.])"
)


def _redact_ipv4(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return value
    return "<redacted:public_ip>" if ip.is_global else value


def _redact_output(output: str) -> str:
    output = OCID_RE.sub("<redacted:ocid>", output)
    output = REQUEST_ID_RE.sub(r"\1<redacted:opc_request_id>", output)
    output = PRIVATE_KEY_RE.sub("<redacted:private_key>", output)
    output = IPV4_RE.sub(_redact_ipv4, output)
    return output


def _run_step(name: str, command: list[str], timeout: int = 2400, *, offline: bool = False) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    if not offline:
        try:
            result = subprocess.run(command, cwd=PROJECT_DIR, capture_output=True, text=True, timeout=timeout, check=False)
            return {
                "name": name, "command": command, "started_at": started,
                "exit_code": result.returncode, "ok": result.returncode == 0,
                "output_tail": _redact_output(result.stdout + result.stderr)[-6000:],
            }
        except subprocess.TimeoutExpired as exc:
            return {"name": name, "command": command, "started_at": started, "exit_code": 124, "ok": False, "output_tail": _redact_output(f"TIMEOUT after {timeout}s: {exc}")}
        except OSError as exc:
            return {"name": name, "command": command, "started_at": started, "exit_code": 127, "ok": False, "output_tail": _redact_output(f"EXECUTION ERROR: {exc}")}
    egress_receipt = Path(tempfile.mkstemp(prefix="logan-offline-egress-")[1])
    egress_receipt.unlink(missing_ok=True)
    env = os.environ.copy()
    # Do not allow ambient cloud, HEC, or credential configuration into an
    # offline gate.  The socket harness is enforced by Python itself.
    for key in list(env):
        if key not in {"PATH", "PYTHONPATH", "LANG", "LC_ALL", "TMPDIR"} and re.search(
            r"(?:token|secret|password|credential|private.?key|access.?key|authorization|oci|aws|azure|splunk|vault|profile)",
            key,
            re.I,
        ):
            env.pop(key, None)
    env["PYTHONPATH"] = str(SCRIPTS_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env["OFFLINE_EGRESS_RECEIPT"] = str(egress_receipt)
    try:
        result = subprocess.run(
            command,
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        output = _redact_output(result.stdout + result.stderr)
        network = {}
        try:
            if egress_receipt.exists():
                network = json.loads(egress_receipt.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            network = {"attempted": True, "kind": "unreadable_receipt"}
        payload = {
            "name": name,
            "command": command,
            "started_at": started,
            "exit_code": result.returncode,
            "ok": result.returncode == 0 and not network.get("attempted", False),
            "output_tail": output[-6000:],
        }
        if network:
            payload["network"] = network
        return payload
    except subprocess.TimeoutExpired as exc:
        return {
            "name": name,
            "command": command,
            "started_at": started,
            "exit_code": 124,
            "ok": False,
            "output_tail": _redact_output(f"TIMEOUT after {timeout}s: {exc}"),
            "network": {"attempted": False},
        }
    except OSError as exc:
        return {
            "name": name,
            "command": command,
            "started_at": started,
            "exit_code": 127,
            "ok": False,
            "output_tail": _redact_output(f"EXECUTION ERROR: {exc}"),
            "network": {"attempted": False},
        }
    finally:
        try:
            egress_receipt.unlink(missing_ok=True)
        except OSError:
            pass


def build_splunk_parallel_offline_steps() -> list[tuple[str, list[str], int]]:
    """Return the credential-free validators in the Splunk parallel release stage."""
    python = sys.executable
    return [
        (
            "registry drift validation",
            [python, str(SCRIPTS_DIR / "generate_splunk_detection_registry.py"), "--check"],
            300,
        ),
        (
            "schema validation",
            [python, "-m", "pytest", "-q", "scripts/test_splunk_detection_registry.py"],
            600,
        ),
        (
            "local exporter success",
            [python, str(SPLUNK_EXPORTER_CLI), "local-e2e", "--scenario", "success"],
            300,
        ),
        (
            "local exporter duplicate",
            [python, str(SPLUNK_EXPORTER_CLI), "local-e2e", "--scenario", "duplicate-invocation"],
            300,
        ),
        (
            "local exporter failure",
            [python, str(SPLUNK_EXPORTER_CLI), "local-e2e", "--scenario", "500"],
            300,
        ),
        (
            "local exporter replay",
            [
                python,
                str(SPLUNK_EXPORTER_CLI),
                "local-e2e",
                "--scenario",
                "approved-replay",
                "--approve-replay",
            ],
            300,
        ),
        (
            "diagram validation",
            [python, "-m", "pytest", "-q", "scripts/test_splunk_diagrams.py"],
            600,
        ),
        (
            "documentation validation",
            [python, "-m", "pytest", "-q", "scripts/test_splunk_documentation.py"],
            600,
        ),
        (
            "terraform format validation",
            [python, str(TERRAFORM_STATIC_VALIDATOR), "--check-format"],
            300,
        ),
        (
            "terraform static validation",
            [python, str(TERRAFORM_STATIC_VALIDATOR)],
            300,
        ),
    ]


def _splunk_evidence_manifest() -> dict[str, object]:
    """Hash every source/input transitively relevant to the offline stage."""
    paths: dict[str, str] = {}
    registry_path = PROJECT_DIR / "queries/splunk_detection_registry.json"
    registry_query_paths: list[Path] = []
    if registry_path.is_file():
        try:
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            registry_query_paths = [PROJECT_DIR / item["oci_query_file"] for item in registry.get("detections", []) if item.get("oci_query_file")]
        except (OSError, json.JSONDecodeError, TypeError):
            registry_query_paths = []
    stage_script_paths = [
        SCRIPTS_DIR / "generate_splunk_detection_registry.py",
        SCRIPTS_DIR / "validate_terraform_static.py",
        SCRIPTS_DIR / "sitecustomize.py",
    ]
    roots = {
        "exporter": [SCRIPTS_DIR / "splunk_evidence_exporter_cli.py", * (SCRIPTS_DIR / "splunk_evidence_exporter").glob("**/*.py")],
        "fixtures": list((SCRIPTS_DIR / "fixtures/splunk_evidence").glob("**/*")),
        "registry": [PROJECT_DIR / "queries/splunk_detection_registry.json"],
        "registry-referenced-queries": registry_query_paths,
        "offline-stage-dependencies": stage_script_paths,
        "schemas-config": [* (PROJECT_DIR / "schemas").glob("splunk_*.json"), PROJECT_DIR / "config/splunk_parallel_delivery.yaml"],
        "release-tests": [PROJECT_DIR / "scripts/release_checklist.py", *SCRIPTS_DIR.glob("test_splunk_*.py"), SCRIPTS_DIR / "test_check_inventory_drift.py"],
        "docs-diagrams": [*PROJECT_DIR.glob("docs/SPLUNK*.md"), *PROJECT_DIR.glob("docs/diagrams/*splunk*"), *PROJECT_DIR.glob("docs/diagrams/*logan*" )],
        "terraform": [* (PROJECT_DIR / "stack").glob("**/*.tf"), * (PROJECT_DIR / "stack").glob("**/*.yaml"), * (PROJECT_DIR / "stack").glob("**/*.yml")],
    }
    missing: list[str] = []
    for category, candidates in roots.items():
        for path in sorted({p for p in candidates if p.is_file()}):
            relative = path.relative_to(PROJECT_DIR).as_posix()
            paths[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        if not candidates:
            missing.append(f"manifest category has no inputs: {category}")
    required = [
        "scripts/splunk_evidence_exporter_cli.py",
        "scripts/generate_splunk_detection_registry.py",
        "scripts/validate_terraform_static.py",
        "scripts/sitecustomize.py",
        "queries/splunk_detection_registry.json",
        "config/splunk_parallel_delivery.yaml",
        "stack/main.tf",
    ]
    missing.extend(path for path in required if path not in paths)
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=PROJECT_DIR, text=True, stderr=subprocess.DEVNULL).strip()
        tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=PROJECT_DIR, text=True, stderr=subprocess.DEVNULL).strip()
        git_version = subprocess.check_output(["git", "--version"], text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        commit = tree = git_version = "unavailable"
    return {"complete": not missing, "missing": sorted(set(missing)), "files": paths, "git_commit": commit, "git_tree": tree, "tool_versions": {"python": sys.version.split()[0], "git": git_version}}


def _scenario_contract_ok(name: str, output: str) -> bool:
    if not name.startswith("local exporter "):
        return True
    try:
        receipt = json.loads(output)
    except json.JSONDecodeError:
        return False
    common = (
        receipt.get("evidence_class") == "locally_verified"
        and receipt.get("provider_validation") == "not_run"
        and receipt.get("provider_verified") is False
    )
    if name == "local exporter success":
        return common and receipt.get("status") == "delivered" and receipt.get("checkpoint_committed") is True
    if name == "local exporter duplicate":
        return (
            common
            and receipt.get("status") == "delivered"
            and receipt.get("invocation_count") == 2
            and receipt.get("stable_event_keys") is True
        )
    if name == "local exporter failure":
        return (
            common
            and receipt.get("status") == "delivery_failed"
            and receipt.get("checkpoint_committed") is False
            and receipt.get("dlq_record_count") == 1
        )
    if name == "local exporter replay":
        return (
            common
            and receipt.get("initial_status") == "delivery_failed"
            and receipt.get("status") == "delivered"
            and receipt.get("replay_approved") is True
            and receipt.get("replay_matches_quarantined_events") is True
        )
    return False


def run_splunk_parallel_offline_stage() -> dict[str, object]:
    """Run and summarize the tenant-neutral Splunk parallel release contracts."""
    gates: list[dict[str, object]] = []
    scenario_passed = 0
    for name, command, timeout in build_splunk_parallel_offline_steps():
        result = _run_step(name, command, timeout, offline=True)
        contract_ok = _scenario_contract_ok(name, result["output_tail"])
        ok = bool(result["ok"] and contract_ok)
        gate = {"name": name, "exit_code": result["exit_code"], "ok": ok}
        if result.get("network"):
            gate["network"] = result["network"]
        gates.append(gate)
        if name.startswith("local exporter ") and ok:
            scenario_passed += 1

    passed = sum(gate["ok"] is True for gate in gates)
    manifest = _splunk_evidence_manifest()
    return {
        "schema_version": "oci.logan.splunk.local-release.v1",
        "status": "PASS" if passed == len(gates) and manifest["complete"] else "FAIL",
        "offline": True,
        "external_calls": [],
        "evidence_class": "locally_verified",
        "provider_validation": "not_run",
        "provider_verified": False,
        "scenario_counts": {
            "requested": 4,
            "passed": scenario_passed,
            "success": 1 if gates[2]["ok"] else 0,
            "duplicate": 1 if gates[3]["ok"] else 0,
            "failure": 1 if gates[4]["ok"] else 0,
            "replay": 1 if gates[5]["ok"] else 0,
        },
        "gate_counts": {
            "total": len(gates),
            "passed": passed,
            "failed": len(gates) - passed,
        },
        "artifact_hashes": manifest["files"],
        "evidence_manifest": manifest,
        "gates": gates,
    }


def build_steps(
    include_live: bool,
    skip_tests: bool,
    lookback: str,
    query_timeout: int,
    require_sentinel_synthetic_hits: bool = False,
) -> list[tuple[str, list[str], int]]:
    python = sys.executable
    steps: list[tuple[str, list[str], int]] = [
        ("log source dry run", [python, str(SCRIPTS_DIR / "setup_log_sources.py"), "--dry-run"], 300),
        ("synthetic log contract validation", [python, str(SCRIPTS_DIR / "validate_synthetic_logs.py")], 300),
        ("threat-intel candidate inventory", [python, str(SCRIPTS_DIR / "content_discovery.py")], 300),
        ("field dictionary validation", [python, str(SCRIPTS_DIR / "field_dictionary.py"), "--validate-query-fields"], 300),
        ("query performance audit", [python, str(SCRIPTS_DIR / "query_performance_audit.py"), "--strict"], 300),
        ("siem discovery schema validation", [python, str(SCRIPTS_DIR / "siem_discovery_report.py"), "sentinel"], 300),
        (
            "migration plan/report validation",
            [
                python,
                str(SCRIPTS_DIR / "siem_discovery_report.py"),
                "report",
                "--report-only",
            ],
            300,
        ),
        ("sentinel feed dependency bundle", [python, str(SCRIPTS_DIR / "sentinel_feed_dependencies.py")], 300),
        ("detection rule spec export", [python, str(SCRIPTS_DIR / "detection_rule_creator.py"), "--write-default"], 300),
        ("osquery pack validation", [python, str(SCRIPTS_DIR / "validate_osquery_packs.py")], 300),
        ("cloud guard instance security synthetic contract", [python, str(SCRIPTS_DIR / "validate_cloud_guard_instance_security.py")], 300),
        ("catalog generation", [python, str(SCRIPTS_DIR / "generate_catalog.py")], 300),
        ("dashboard inventory export", [python, str(SCRIPTS_DIR / "deploy_dashboard.py"), "--export-inventory"], 300),
        ("octo apm workshop bundle validation", [python, str(SCRIPTS_DIR / "octo_apm_workshop.py"), "--validate-bundle"], 300),
        # Keep the independent local Splunk evidence result before the known
        # Sentinel drift gate, so a Sentinel blocker cannot hide it.
        (
            "splunk parallel offline release",
            [python, str(SCRIPTS_DIR / "release_checklist.py"), "--splunk-parallel-offline-stage"],
            2400,
        ),
        ("sentinel strict status", [python, str(SCRIPTS_DIR / "sentinel_conversion_workflow.py"), "status", "--json", "--strict"], 300),
        ("sentinel drift check", [python, str(SCRIPTS_DIR / "sentinel_drift_check.py")], 300),
        ("dashboard dry run", [python, str(SCRIPTS_DIR / "deploy_dashboard.py"), "--dry-run", "--skip-live-validation"], 300),
        # Drift check runs AFTER all generators that produce its inputs
        # (catalog.json, dashboard_inventory.json). sentinel_conversion_report.json
        # is not regenerated here — it ships fresh from sentinel_conversion_workflow.py
        # and is treated as an input artifact for the release window.
        ("inventory drift check", [python, str(SCRIPTS_DIR / "check_inventory_drift.py")], 60),
        ("sensitive value scan", [python, str(SCRIPTS_DIR / "scan_sensitive_values.py")], 300),
        ("compileall scripts", [python, "-m", "compileall", "-q", "scripts"], 300),
    ]
    if require_sentinel_synthetic_hits:
        drift_index = next(index for index, step in enumerate(steps) if step[0] == "sentinel drift check")
        steps.insert(
            drift_index + 1,
            (
                "sentinel synthetic-hit drift check",
                [python, str(SCRIPTS_DIR / "sentinel_drift_check.py"), "--require-synthetic-hits"],
                300,
            ),
        )
    if not skip_tests:
        steps.append(("pytest", [python, "-m", "pytest", "-q"], 1200))
    if include_live:
        parse_path = HEALTH_DIR / "parse-validate-all.json"
        steps.append((
            "live query parse validation",
            [
                python,
                str(SCRIPTS_DIR / "parse_validate_all_queries.py"),
                "--json",
                str(parse_path),
            ],
            1800,
        ))
        verify_path = HEALTH_DIR / "all-dashboard-verify.json"
        steps.append((
            "live profile dashboard verification",
            [
                python,
                str(SCRIPTS_DIR / "verify_deployed_dashboards.py"),
                "--lookback",
                lookback,
                "--query-timeout",
                str(query_timeout),
                "--json",
                str(verify_path),
            ],
            3600,
        ))
    return steps


def _sentinel_backlog_advisory(path: Path = SENTINEL_BACKLOG_PRIORITY_PATH) -> dict:
    if not path.exists():
        return {"available": False, "text": "Sentinel backlog: not ranked"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"available": False, "text": f"Sentinel backlog: unreadable ({exc})"}
    summary = payload.get("summary", {})
    ranked = int(summary.get("ranked_count", 0) or 0)
    blocker = str(summary.get("top_blocker", "") or "none")
    return {
        "available": True,
        "ranked_count": ranked,
        "top_blocker": blocker,
        "text": f"Sentinel backlog: {ranked} ranked; top blocker: {blocker}",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run release checklist gates")
    parser.add_argument("--include-live", action="store_true", help="Run live dashboard verification for the active OCI_PROFILE")
    parser.add_argument("--skip-tests", action="store_true", help="Skip unittest discovery")
    parser.add_argument("--lookback", default="21d", help="Live verification lookback when --include-live is set")
    parser.add_argument("--query-timeout", type=int, default=60, help="Live query timeout when --include-live is set")
    parser.add_argument(
        "--require-sentinel-synthetic-hits",
        action="store_true",
        help="Require every promoted Sentinel artifact to have non-empty synthetic live-hit evidence.",
    )
    parser.add_argument("--report", help="Optional release evidence JSON path")
    parser.add_argument("--handoff-summary", action="store_true", help="Write docs/health/latest-handoff.json after a passing run")
    parser.add_argument("--handoff-out", default=str(HEALTH_DIR / "latest-handoff.json"), help="Handoff summary path when --handoff-summary is set")
    parser.add_argument(
        "--splunk-parallel-offline-stage",
        action="store_true",
        help="Run only the credential-free Splunk parallel release stage and print JSON",
    )
    args = parser.parse_args()

    if args.splunk_parallel_offline_stage:
        if args.include_live:
            parser.error("the Splunk parallel offline stage cannot include live validation")
        evidence = run_splunk_parallel_offline_stage()
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0 if evidence["status"] == "PASS" else 1

    HEALTH_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    report_path = Path(args.report) if args.report else HEALTH_DIR / f"release-checklist-{timestamp}.json"

    results = []
    splunk_parallel_evidence = None
    print("=" * 70)
    print("OCI Log Analytics Detection Engine Release Checklist")
    print("=" * 70)
    for name, command, timeout in build_steps(
        args.include_live,
        args.skip_tests,
        args.lookback,
        args.query_timeout,
        args.require_sentinel_synthetic_hits,
    ):
        print(f"\n[{len(results) + 1}] {name}")
        result = _run_step(name, command, timeout=timeout)
        results.append(result)
        if name == "splunk parallel offline release":
            try:
                splunk_parallel_evidence = json.loads(result["output_tail"])
            except (TypeError, json.JSONDecodeError):
                splunk_parallel_evidence = {"status": "UNREADABLE", "evidence_class": "unverified"}
        status = "PASS" if result["ok"] else "FAIL"
        print(f"  {status} exit={result['exit_code']}")
        if not result["ok"]:
            print(result["output_tail"][-2000:])
            break

    report = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "include_live": args.include_live,
        "require_sentinel_synthetic_hits": args.require_sentinel_synthetic_hits,
        "overall_status": "PASS" if all(result["ok"] for result in results) else "FAIL",
        "steps": results,
        "splunk_parallel_offline_stage": splunk_parallel_evidence,
        "advisories": {
            "sentinel_backlog": _sentinel_backlog_advisory(),
        },
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(report["advisories"]["sentinel_backlog"]["text"])
    print(f"\nRelease evidence: {report_path}")
    if args.handoff_summary and report["overall_status"] == "PASS":
        from handoff_summary import write_summary

        write_summary(report_path, out=Path(args.handoff_out), project_dir=PROJECT_DIR)
        print(f"Handoff summary: {args.handoff_out}")
    return 0 if report["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
