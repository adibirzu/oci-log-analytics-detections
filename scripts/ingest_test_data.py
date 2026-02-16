"""
Upload test attack logs to OCI Log Analytics.

Supports two ingestion modes:
  --mode direct     Upload directly via Log Analytics Upload API (default)
  --mode streaming  Publish to OCI Streaming (requires setup_streaming_pipeline.py)

Architecture:
  Direct:    This script -> OCI Log Analytics Upload API -> Log Analytics
  Streaming: This script -> OCI Streaming -> Service Connector Hub -> Log Analytics

Prerequisites:
  1. OCI CLI configured (~/.oci/config)
  2. Log Analytics service enabled in the tenancy
  3. Run generate_test_logs.py first to create test data files
  4. (Streaming mode only) Run setup_streaming_pipeline.py first

Usage:
  python3 scripts/generate_test_logs.py
  python3 scripts/ingest_test_data.py                # Direct upload (default)
  python3 scripts/ingest_test_data.py --mode streaming  # Via OCI Streaming
"""

import json
import os
import sys
import io
import base64
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_config import (
    TENANCY_ID, COMPARTMENT_ID, PROJECT_DIR, TEST_DATA_DIR,
    LOG_GROUP_NAME,
    get_oci_config, get_la_client, get_namespace, ensure_log_group,
    validate_oci_setup,
    SOURCE_CANDIDATE_GROUPS,
    list_available_log_sources,
    resolve_source_from_candidates,
)

import oci

STREAMING_CONFIG_PATH = os.path.join(PROJECT_DIR, 'config', 'streaming_config.json')

# Maps test data files to their OCI Log Analytics log sources
UPLOAD_MANIFEST = [
    {
        "filename": "oci_audit.jsonl",
        "source_candidates": SOURCE_CANDIDATE_GROUPS["oci_audit"],
        "upload_name": "soc-test-oci-audit",
        "stream_key": "soc-detection-oci-audit",
        "content_type": "application/octet-stream",
        "description": "OCI Audit events (IAM, Network, Compute, Storage, KMS, DB, WAF, Console)"
    },
    {
        "filename": "cloud_guard.jsonl",
        "source_candidates": SOURCE_CANDIDATE_GROUPS["cloud_guard"],
        "upload_name": "soc-test-cloud-guard",
        "stream_key": "soc-detection-cloud-guard",
        "content_type": "application/octet-stream",
        "description": "Cloud Guard problem detection events"
    },
    {
        "filename": "linux_syslog.jsonl",
        "source_candidates": SOURCE_CANDIDATE_GROUPS["linux_syslog"],
        "upload_name": "soc-test-linux",
        "stream_key": "soc-detection-linux-audit",
        "content_type": "application/octet-stream",
        "description": "Linux attacks (SSH, sudo, reverse shell, GTFOBins, persistence)"
    },
    {
        "filename": "windows_sysmon.jsonl",
        "source_candidates": SOURCE_CANDIDATE_GROUPS["windows_sysmon"],
        "upload_name": "soc-test-windows",
        "stream_key": "soc-detection-windows-sysmon",
        "content_type": "application/octet-stream",
        "description": "Windows Sysmon events (LOLBins, encoded PS, credential dumping)"
    },
    {
        "filename": "windows_event_security.jsonl",
        "source_candidates": SOURCE_CANDIDATE_GROUPS["windows_event_security"],
        "upload_name": "soc-test-winsec",
        "stream_key": "soc-detection-winsec",
        "content_type": "application/octet-stream",
        "description": "Windows Security Event Log (logon, privilege, account, audit)"
    },
    {
        "filename": "windows_event_system.jsonl",
        "source_candidates": SOURCE_CANDIDATE_GROUPS["windows_event_system"],
        "upload_name": "soc-test-winsys",
        "stream_key": "soc-detection-winsys",
        "content_type": "application/octet-stream",
        "description": "Windows System Event Log (service install, system changes)"
    },
    {
        "filename": "linux_secure.jsonl",
        "source_candidates": SOURCE_CANDIDATE_GROUPS["linux_secure"],
        "upload_name": "soc-test-linsec",
        "stream_key": "soc-detection-linsec",
        "content_type": "application/octet-stream",
        "description": "Linux auth/secure logs (SSH, sudo, account, persistence)"
    },
    {
        "filename": "sysmon_operational.jsonl",
        "source_candidates": SOURCE_CANDIDATE_GROUPS["sysmon_operational"],
        "upload_name": "soc-test-sysmon-op",
        "stream_key": "soc-detection-sysmon-op",
        "content_type": "application/octet-stream",
        "description": "Windows Sysmon Operational (process, network, DNS, file, injection)"
    },
]


# ─── Direct Upload Mode ──────────────────────────────────────────

def upload_direct(la_client, namespace, log_group_id, entry, resolved_log_source):
    """Upload a test log file directly via the Log Analytics Upload API."""
    filepath = os.path.join(TEST_DATA_DIR, entry['filename'])
    if not os.path.exists(filepath):
        print(f"  SKIP: {entry['filename']} not found")
        return False

    file_size = os.path.getsize(filepath)
    print(f"\n  Uploading: {entry['filename']} ({file_size} bytes)")
    print(f"    Log Source: {resolved_log_source}")

    with open(filepath, 'rb') as f:
        file_body = io.BytesIO(f.read())

    try:
        response = la_client.upload_log_file(
            namespace_name=namespace,
            upload_name=entry['upload_name'],
            log_source_name=resolved_log_source,
            filename=entry['filename'],
            opc_meta_loggrpid=log_group_id,
            upload_log_file_body=file_body,
            content_type=entry['content_type'],
            char_encoding="UTF-8"
        )
        print(f"    Status: {response.status}")
        req_id = response.headers.get('opc-request-id', 'N/A')
        obj_ref = response.headers.get('opc-object-id', 'N/A')
        print(f"    Request ID: {req_id}")
        print(f"    Object Ref: {obj_ref}")
        return True
    except oci.exceptions.ServiceError as e:
        print(f"    ERROR ({e.status}): {e.message}")
        if "LogSource" in str(e.message) or "log source" in str(e.message).lower():
            print(f"    HINT: Log source '{resolved_log_source}' may not exist.")
            print(f"    Candidates: {entry['source_candidates']}")
            print(f"    Create it: OCI Console > Log Analytics > Administration > Sources")
        return False


def run_direct_mode():
    """Upload test data directly to Log Analytics."""
    print("\n[1/3] Connecting to OCI Log Analytics...")
    la_client = get_la_client()

    print("\n[2/3] Setting up namespace and log group...")
    namespace = get_namespace(la_client)
    log_group_id = ensure_log_group(la_client, namespace)
    available_sources = list_available_log_sources(la_client, namespace, COMPARTMENT_ID)
    print(f"  Discovered {len(available_sources)} available log sources")

    print("\n[3/3] Uploading test log files...")
    results = {}
    for entry in UPLOAD_MANIFEST:
        resolved = resolve_source_from_candidates(available_sources, entry["source_candidates"])
        if not resolved:
            resolved = entry["source_candidates"][0]
            print(f"\n  WARN: None of {entry['source_candidates']} found; using '{resolved}'")
        success = upload_direct(la_client, namespace, log_group_id, entry, resolved)
        results[entry['filename']] = success

    # Verify
    print("\n  Checking recent uploads...")
    try:
        uploads = la_client.list_uploads(
            namespace_name=namespace,
            name_contains="soc-test"
        ).data.items
        for u in uploads:
            print(f"    - {u.name} ({u.time_created})")
        if not uploads:
            print("    (uploads may take a minute to appear)")
    except Exception as e:
        print(f"    Could not list uploads: {e}")

    return results


# ─── Streaming Mode ───────────────────────────────────────────────

def read_messages(filepath):
    """Split a NDJSON file into individual messages for streaming."""
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def publish_to_stream(stream_client, stream_id, messages, name):
    """Publish messages to an OCI Streaming stream in batches."""
    print(f"\n  Publishing {len(messages)} messages to: {name}")
    total_published = 0
    total_failed = 0

    # Batch into groups of 50
    for i in range(0, len(messages), 50):
        batch = messages[i:i+50]
        entries = []
        for j, msg in enumerate(batch):
            entries.append(oci.streaming.models.PutMessagesDetailsEntry(
                key=base64.b64encode(f"detection-{i+j}".encode()).decode(),
                value=base64.b64encode(msg.encode('utf-8')).decode()
            ))

        details = oci.streaming.models.PutMessagesDetails(messages=entries)
        try:
            response = stream_client.put_messages(stream_id, details)
            failures = response.data.failures or 0
            total_published += len(entries) - failures
            total_failed += failures
        except oci.exceptions.ServiceError as e:
            print(f"    ERROR: {e.status} - {e.message}")
            total_failed += len(entries)

    print(f"    Published: {total_published}, Failed: {total_failed}")
    return total_published, total_failed


def run_streaming_mode():
    """Publish test data to OCI Streaming."""
    if not os.path.exists(STREAMING_CONFIG_PATH):
        print(f"ERROR: {STREAMING_CONFIG_PATH} not found.")
        print("Run: python3 scripts/setup_streaming_pipeline.py")
        sys.exit(1)

    with open(STREAMING_CONFIG_PATH, 'r') as f:
        streaming_config = json.load(f)

    config = get_oci_config()
    results = {}

    for entry in UPLOAD_MANIFEST:
        filepath = os.path.join(TEST_DATA_DIR, entry['filename'])
        if not os.path.exists(filepath):
            print(f"\n  SKIP: {entry['filename']}")
            continue

        stream_key = entry['stream_key']
        if stream_key not in streaming_config:
            print(f"\n  SKIP: Stream '{stream_key}' not configured")
            continue

        info = streaming_config[stream_key]
        print(f"\n  --- {entry['description']} ---")
        print(f"  Stream: {stream_key} -> {info['log_source']}")

        stream_client = oci.streaming.StreamClient(
            config, service_endpoint=info['messages_endpoint']
        )
        messages = read_messages(filepath)
        published, _ = publish_to_stream(
            stream_client, info['stream_id'], messages, stream_key
        )
        results[entry['filename']] = published > 0

    return results


# ─── Main ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Upload test logs to OCI Log Analytics")
    parser.add_argument('--mode', choices=['direct', 'streaming'], default='direct',
                        help='Ingestion mode: direct (Upload API) or streaming (OCI Streaming)')
    parser.add_argument('--validate', action='store_true',
                        help='Run pre-flight validation checks')
    args = parser.parse_args()

    if args.validate:
        ok = validate_oci_setup(['ocid', 'cli', 'namespace', 'test_data', 'log_sources'])
        sys.exit(0 if ok else 1)

    print("=" * 60)
    print(f"OCI Log Analytics - Test Data Ingestion ({args.mode} mode)")
    print("=" * 60)

    if not os.path.exists(TEST_DATA_DIR):
        print(f"ERROR: {TEST_DATA_DIR} not found. Run generate_test_logs.py first.")
        sys.exit(1)

    if args.mode == 'direct':
        results = run_direct_mode()
    else:
        results = run_streaming_mode()

    # Summary
    print("\n" + "=" * 60)
    print("Upload Summary")
    print("=" * 60)
    for filename, success in results.items():
        status = "OK" if success else "FAILED"
        print(f"  [{status}] {filename}")

    succeeded = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n  {succeeded}/{total} uploads completed successfully.")

    if succeeded > 0:
        wait_time = "2-3 minutes" if args.mode == 'direct' else "3-5 minutes"
        print(f"\n  Next steps:")
        print(f"  1. Wait {wait_time} for log processing")
        print(f"  2. Go to OCI Console > Log Analytics > Log Explorer")
        print(f"  3. Filter by Log Group = '{LOG_GROUP_NAME}'")
        print(f"  4. Run saved searches to verify detection rules trigger")
        print(f"  5. Deploy dashboards: python3 scripts/deploy_dashboard.py --cleanup")


if __name__ == "__main__":
    main()
