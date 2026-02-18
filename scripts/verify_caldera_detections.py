#!/usr/bin/env python3
"""Post-Caldera detection verification.

Queries OCI Log Analytics to confirm that expected detection rules fired
after Caldera adversary operations.  Implements the Zen principle:
"If you can detect it, you can test it."

Usage:
  python3 scripts/verify_caldera_detections.py               # Full verification
  python3 scripts/verify_caldera_detections.py --operation discovery  # Single op
  python3 scripts/verify_caldera_detections.py --lookback 2h  # Custom time window
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_config import (
    require_oci_config, get_la_client, get_namespace,
    COMPARTMENT_ID, QUERIES_DIR,
)

# ─── Expected detections per Caldera operation ────────────────

OPERATION_DETECTIONS = {
    "discovery": {
        "techniques": ["T1082", "T1016", "T1049", "T1033"],
        "expected_rules": [
            "windows_account_discovery_commands",
            "windows_remote_system_discovery",
            "linux_system_owner_and_user_discovery",
        ],
        "queries": [
            "'Log Source' = 'Windows Sysmon Events' and 'Command Line' like '*whoami*'",
            "'Log Source' = 'Windows Sysmon Events' and 'Command Line' like '*systeminfo*'",
            "'Log Source' = 'Windows Sysmon Events' and 'Command Line' like '*ipconfig*'",
        ],
    },
    "credential-access": {
        "techniques": ["T1003.001", "T1558.003", "T1552"],
        "expected_rules": [
            "windows_lsass_memory_access",
            "windows_credential_dumping_via_procdump",
            "windows_kerberoasting_attack",
        ],
        "queries": [
            "'Log Source' = 'Windows Sysmon Events' and 'Command Line' like '*lsass*'",
            "'Log Source' = 'Windows Sysmon Events' and 'Command Line' like '*mimikatz*'",
            "'Log Source' = 'Windows Sysmon Events' and 'Command Line' like '*procdump*'",
        ],
    },
    "lateral-movement": {
        "techniques": ["T1021.002", "T1021.006", "T1570"],
        "expected_rules": [
            "windows_psexec_remote_execution",
            "sysmon_lateral_movement_via_smb",
            "sysmon_lateral_movement_via_winrm",
        ],
        "queries": [
            "'Log Source' = 'Windows Sysmon Events' and 'Command Line' like '*PsExec*'",
            "'Log Source' = 'Windows Sysmon Events' and 'Pipe Name' like '*psexec*'",
        ],
    },
    "collection": {
        "techniques": ["T1005", "T1039", "T1074"],
        "expected_rules": [
            "linux_sensitive_data_collection_from_local_system",
            "windows_data_staging_for_exfiltration",
        ],
        "queries": [
            "'Log Source' = 'SOC Linux Syslog Logs' and msg like '*find*' and msg like '*-name*'",
        ],
    },
    "exfiltration": {
        "techniques": ["T1041", "T1048", "T1567"],
        "expected_rules": [
            "linux_exfiltration_over_alternative_protocol",
            "sysmon_dns_data_exfiltration",
        ],
        "queries": [
            "'Log Source' = 'Windows Sysmon Events' and 'Query Name' like '*.*.*.*.*'",
        ],
    },
}


def run_query(la_client, namespace, query, lookback="1h"):
    """Execute an OCL query against OCI Log Analytics."""
    import oci
    try:
        result = la_client.query(
            namespace_name=namespace,
            query_details=oci.log_analytics.models.QueryDetails(
                compartment_id=COMPARTMENT_ID,
                query_string=query,
                sub_system="LOG",
                max_total_count=10,
                time_filter=oci.log_analytics.models.TimeRange(
                    time_start=None,
                    time_end=None,
                    time_type="RELATIVE_TIME",
                    relative_time=f"LAST_{lookback.upper()}",
                ),
            ),
        )
        items = result.data.items if hasattr(result.data, 'items') else []
        return len(items)
    except Exception as e:
        print(f"    Query error: {e}")
        return -1


def verify_operation(la_client, namespace, op_name, lookback):
    """Verify detections for a single Caldera operation."""
    config = OPERATION_DETECTIONS.get(op_name)
    if not config:
        print(f"  Unknown operation: {op_name}")
        return False

    print(f"\n  --- {op_name.upper()} ---")
    print(f"  Techniques: {', '.join(config['techniques'])}")
    print(f"  Expected rules: {', '.join(config['expected_rules'])}")

    total_hits = 0
    total_queries = len(config['queries'])
    for query in config['queries']:
        count = run_query(la_client, namespace, query, lookback)
        status = "HIT" if count > 0 else ("ERROR" if count < 0 else "MISS")
        print(f"    [{status:5s}] {query[:80]}... ({count} results)")
        if count > 0:
            total_hits += 1

    coverage = (total_hits / total_queries * 100) if total_queries else 0
    print(f"  Coverage: {total_hits}/{total_queries} queries matched ({coverage:.0f}%)")
    return total_hits > 0


def main():
    parser = argparse.ArgumentParser(description="Verify Caldera detection coverage")
    parser.add_argument("--operation", choices=list(OPERATION_DETECTIONS.keys()),
                        help="Verify a single operation")
    parser.add_argument("--lookback", default="1h",
                        help="Time window for query lookback (default: 1h)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print expected detections without querying OCI")
    args = parser.parse_args()

    print("=" * 60)
    print("  Caldera Detection Verification")
    print("=" * 60)
    print(f"  Lookback: {args.lookback}")

    if args.dry_run:
        operations = [args.operation] if args.operation else list(OPERATION_DETECTIONS.keys())
        for op_name in operations:
            config = OPERATION_DETECTIONS[op_name]
            print(f"\n  --- {op_name.upper()} ---")
            print(f"  Techniques: {', '.join(config['techniques'])}")
            for rule in config['expected_rules']:
                print(f"    Expected: {rule}")
            for query in config['queries']:
                print(f"    Query: {query[:80]}...")
        print("\n  (dry run — no OCI queries executed)")
        return

    require_oci_config()
    la_client = get_la_client()
    namespace = get_namespace(la_client)

    operations = [args.operation] if args.operation else list(OPERATION_DETECTIONS.keys())
    results = {}
    for op_name in operations:
        results[op_name] = verify_operation(la_client, namespace, op_name, args.lookback)

    # Summary
    print(f"\n{'=' * 60}")
    print("  Verification Summary")
    print(f"{'=' * 60}")
    for op_name, detected in results.items():
        status = "PASS" if detected else "FAIL"
        print(f"  [{status}] {op_name}")

    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n  {passed}/{total} operations had at least one detection")

    if passed < total:
        print("\n  Possible reasons for FAIL:")
        print("    - Caldera operations haven't completed yet")
        print("    - Log ingestion delay (try --lookback 2h)")
        print("    - Agent not deployed on target hosts")
        print("    - Log source not configured in OCI LA")


if __name__ == "__main__":
    main()
