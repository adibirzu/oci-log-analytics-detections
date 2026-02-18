"""
Set up the OCI Streaming → Log Analytics pipeline.

Creates:
  1. A Streaming stream (Kafka-compatible) for each log category
  2. A Service Connector Hub connector per stream that routes messages to Log Analytics

Architecture:
  Test Logs → OCI Streaming Stream → Service Connector Hub → OCI Log Analytics

Prerequisites:
  1. OCI CLI configured (~/.oci/config)
  2. Log Analytics enabled with namespace onboarded
  3. Required IAM policies:
     - Allow group <group> to manage streams in compartment <compartment>
     - Allow group <group> to manage serviceconnectors in compartment <compartment>
     - Allow group <group> to manage log-analytics-log-group in compartment <compartment>
     - Allow service serviceconnector to use stream-pull in compartment <compartment>
     - Allow service serviceconnector to {READ_LOG_CONTENT} log-content in compartment <compartment>

Usage:
  python3 scripts/setup_streaming_pipeline.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_config import (
    TENANCY_ID, COMPARTMENT_ID, LOG_GROUP_ID, _cfg,
    get_la_client, get_streaming_admin_client, get_sch_client,
    get_namespace, ensure_log_group, validate_oci_setup,
    require_oci_config,
    SOURCE_CANDIDATE_GROUPS, LOG_GROUP_NAME, LOG_GROUP_DESC,
    list_available_log_sources,
    resolve_source_from_candidates,
)

import oci

# Stream configurations — one stream per log source category
STREAMS = [
    {
        "name": "soc-detection-oci-audit",
        "partitions": 1,
        "retention_hours": 24,
        "source_candidates": SOURCE_CANDIDATE_GROUPS["oci_audit"],
    },
    {
        "name": "soc-detection-cloud-guard",
        "partitions": 1,
        "retention_hours": 24,
        "source_candidates": SOURCE_CANDIDATE_GROUPS["cloud_guard"],
    },
    {
        "name": "soc-detection-linux-audit",
        "partitions": 1,
        "retention_hours": 24,
        "source_candidates": SOURCE_CANDIDATE_GROUPS["linux_syslog"],
    },
    {
        "name": "soc-detection-windows-sysmon",
        "partitions": 1,
        "retention_hours": 24,
        "source_candidates": SOURCE_CANDIDATE_GROUPS["windows_sysmon"],
    }
]

TARGET_STREAM_POOL_ID = (
    _cfg("OCI_STREAM_POOL_OCID", "")
    or _cfg("C3_STREAM_POOL_OCID", "")
    or _cfg("OCI_KAFKA_CONNECT_STREAM_POOL_OCID", "")
)


def _wait_for_connector_deleted(sch_client, connector_id, timeout_seconds=180, poll_seconds=5):
    """Wait until a connector no longer exists (404) or is marked DELETED."""
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            data = sch_client.get_service_connector(connector_id).data
            if getattr(data, "lifecycle_state", "") == "DELETED":
                return True
        except oci.exceptions.ServiceError as e:
            if e.status == 404:
                return True
        time.sleep(poll_seconds)
    return False


def _wait_for_active_connector_by_name(sch_client, connector_name, timeout_seconds=300, poll_seconds=10):
    """Wait for a connector with display name to become ACTIVE and return its ID."""
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        items = sch_client.list_service_connectors(
            compartment_id=COMPARTMENT_ID,
            display_name=connector_name
        ).data.items
        for item in items:
            if getattr(item, "lifecycle_state", "") == "ACTIVE":
                return item.id
        time.sleep(poll_seconds)
    return None


def find_or_create_stream(stream_admin_client, stream_config):
    """Find an existing stream by name or create a new one."""
    # Search for existing stream
    streams = stream_admin_client.list_streams(
        compartment_id=COMPARTMENT_ID,
        name=stream_config['name'],
        lifecycle_state="ACTIVE"
    ).data

    if streams:
        if TARGET_STREAM_POOL_ID:
            for stream in streams:
                if getattr(stream, "stream_pool_id", None) == TARGET_STREAM_POOL_ID:
                    print(f"  Stream exists in target pool: {stream.name} ({stream.id})")
                    return stream.id, stream.messages_endpoint
            print(
                f"  Stream '{stream_config['name']}' exists outside target pool; "
                f"creating/using one in target pool {TARGET_STREAM_POOL_ID}."
            )
        else:
            stream = streams[0]
            print(f"  Stream exists: {stream.name} ({stream.id})")
            return stream.id, stream.messages_endpoint

    # Create new stream
    print(f"  Creating Stream: {stream_config['name']}")
    details_kwargs = dict(
        name=stream_config['name'],
        partitions=stream_config['partitions'],
        retention_in_hours=stream_config['retention_hours']
    )
    if TARGET_STREAM_POOL_ID:
        # OCI Streaming API rejects create requests that include BOTH compartment_id and stream_pool_id.
        details_kwargs["stream_pool_id"] = TARGET_STREAM_POOL_ID
    else:
        details_kwargs["compartment_id"] = COMPARTMENT_ID
    details = oci.streaming.models.CreateStreamDetails(**details_kwargs)
    new_stream = stream_admin_client.create_stream(details).data
    print(f"  Created Stream: {new_stream.id} (waiting for ACTIVE state...)")

    # Wait for stream to become active
    for _ in range(30):
        stream_state = stream_admin_client.get_stream(new_stream.id).data
        if stream_state.lifecycle_state == "ACTIVE":
            print(f"  Stream is ACTIVE: {stream_state.messages_endpoint}")
            return stream_state.id, stream_state.messages_endpoint
        time.sleep(2)

    print("  ERROR: Stream not ACTIVE after 60s — aborting.")
    print(f"  Stream ID: {new_stream.id}")
    print("  Check the OCI Console for stream status and retry.")
    sys.exit(1)


def create_service_connector(sch_client, stream_id, stream_name, log_source,
                             log_group_id, la_namespace):
    """Create a Service Connector Hub connector: Streaming → Log Analytics."""
    connector_name = f"sch-{stream_name}-to-la"

    # Check if connector already exists
    existing = sch_client.list_service_connectors(
        compartment_id=COMPARTMENT_ID,
        display_name=connector_name,
        lifecycle_state="ACTIVE"
    ).data.items

    if existing:
        for connector in existing:
            connector_id = connector.id
            full = sch_client.get_service_connector(connector_id).data
            source = getattr(full, "source", None)
            target = getattr(full, "target", None)
            existing_stream_id = getattr(source, "stream_id", None) if source else None
            existing_log_group = getattr(target, "log_group_id", None) if target else None
            existing_log_source = getattr(target, "log_source_identifier", None) if target else None
            if (
                getattr(source, "kind", "") == "streaming"
                and getattr(target, "kind", "") == "loggingAnalytics"
                and existing_stream_id == stream_id
                and existing_log_group == log_group_id
                and existing_log_source == log_source
            ):
                print(f"  Connector exists and is aligned: {connector_name} ({connector_id})")
                return connector_id

            print(f"  Connector drift detected: {connector_name} ({connector_id})")
            print(f"    Current stream: {existing_stream_id}")
            print(f"    Desired stream: {stream_id}")
            print("    Recreating connector with correct source stream...")
            sch_client.delete_service_connector(connector_id)
            _wait_for_connector_deleted(sch_client, connector_id)

    print(f"  Creating Service Connector: {connector_name}")
    print(f"    Source: Streaming ({stream_name})")
    print(f"    Target: Log Analytics ({log_source})")

    source = oci.sch.models.StreamingSourceDetails(
        kind="streaming",
        stream_id=stream_id
    )

    target = oci.sch.models.LoggingAnalyticsTargetDetails(
        kind="loggingAnalytics",
        log_group_id=log_group_id,
        log_source_identifier=log_source
    )

    details = oci.sch.models.CreateServiceConnectorDetails(
        display_name=connector_name,
        description=f"Routes {stream_name} stream to Log Analytics ({log_source})",
        compartment_id=COMPARTMENT_ID,
        source=source,
        target=target
    )

    try:
        response = sch_client.create_service_connector(details)
        work_request_id = response.headers.get('opc-work-request-id', 'pending')
        print(f"  Connector creation initiated (work request: {work_request_id})")
        connector_id = _wait_for_active_connector_by_name(sch_client, connector_name)
        if connector_id:
            print(f"  Connector is ACTIVE: {connector_id}")
            return connector_id
        print(f"  WARNING: connector '{connector_name}' not ACTIVE yet; work request: {work_request_id}")
        return work_request_id
    except oci.exceptions.ServiceError as e:
        print(f"  ERROR creating connector: {e.message}")
        return None


def save_pipeline_config(stream_configs):
    """Save stream OCIDs and endpoints for use by ingest_test_data.py."""
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'config', 'streaming_config.json'
    )
    import json
    with open(config_path, 'w') as f:
        json.dump(stream_configs, f, indent=2)
    print(f"\n  Pipeline config saved to: {config_path}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Set up OCI Streaming → Log Analytics pipeline")
    parser.add_argument("--validate", action="store_true", help="Run pre-flight validation checks")
    parser.add_argument("--dry-run", action="store_true", help="Print plan without executing")
    args = parser.parse_args()

    if args.validate:
        ok = validate_oci_setup(['ocid', 'cli', 'namespace', 'compartment'])
        sys.exit(0 if ok else 1)

    print("=" * 60)
    print("OCI Streaming → Log Analytics Pipeline Setup")
    print("=" * 60)

    if args.dry_run:
        print("\n  [DRY RUN] No changes will be made.\n")
        print(f"  Compartment: {COMPARTMENT_ID}")
        if TARGET_STREAM_POOL_ID:
            print(f"  Target stream pool: {TARGET_STREAM_POOL_ID}")
        else:
            print("  Target stream pool: <not set, OCI default placement>")
        print(f"  Streams to create: {len(STREAMS)}")
        for sc in STREAMS:
            print(f"    - {sc['name']} ({sc['partitions']} partitions, {sc['retention_hours']}h retention)")
            print(f"      → Service Connector → Log Analytics (candidates: {sc['source_candidates']})")
        print(f"\n  Log Group: {LOG_GROUP_NAME}")
        return

    require_oci_config()
    stream_admin_client = get_streaming_admin_client()
    la_client = get_la_client()
    sch_client = get_sch_client()

    # Step 1: Log Analytics namespace and log group
    print("\n[1/4] Setting up Log Analytics...")
    la_namespace = get_namespace(la_client)
    log_group_id = ensure_log_group(la_client, la_namespace)

    # Cross-check: warn if runtime log_group_id differs from env var
    if LOG_GROUP_ID and log_group_id != LOG_GROUP_ID:
        print(f"\n  WARNING: Runtime log_group_id differs from LOG_GROUP_ID env var!")
        print(f"    runtime: {log_group_id}")
        print(f"    env:     {LOG_GROUP_ID}")
        print("    Connectors will use the runtime value. Update .env.local if needed.")
    available_sources = list_available_log_sources(la_client, la_namespace, COMPARTMENT_ID)
    print(f"  Discovered {len(available_sources)} available log sources")

    # Step 2: Create streams
    print("\n[2/4] Setting up Streaming streams...")
    stream_configs = {}
    for sc in STREAMS:
        stream_id, messages_endpoint = find_or_create_stream(stream_admin_client, sc)
        resolved_source = resolve_source_from_candidates(available_sources, sc["source_candidates"])
        if not resolved_source:
            resolved_source = sc["source_candidates"][0]
            print(f"  WARN: None of {sc['source_candidates']} found; using '{resolved_source}'")
        else:
            print(f"  Using log source '{resolved_source}' for stream '{sc['name']}'")
        stream_configs[sc['name']] = {
            "stream_id": stream_id,
            "messages_endpoint": messages_endpoint,
            "log_source": resolved_source
        }

    # Step 3: Create Service Connector Hub connectors
    print("\n[3/4] Setting up Service Connector Hub...")
    for sc in STREAMS:
        cfg = stream_configs[sc['name']]
        create_service_connector(
            sch_client,
            stream_id=cfg['stream_id'],
            stream_name=sc['name'],
            log_source=cfg['log_source'],
            log_group_id=log_group_id,
            la_namespace=la_namespace
        )

    # Step 4: Post-creation validation
    print("\n[4/4] Verifying connector states...")
    all_active = True
    for sc in STREAMS:
        connector_name = f"sch-{sc['name']}-to-la"
        connectors = sch_client.list_service_connectors(
            compartment_id=COMPARTMENT_ID, display_name=connector_name
        ).data.items
        active = [c for c in connectors if getattr(c, "lifecycle_state", "") == "ACTIVE"]
        if active:
            print(f"  [OK  ] {connector_name}")
        else:
            states = [getattr(c, "lifecycle_state", "?") for c in connectors]
            print(f"  [WAIT] {connector_name} — state(s): {states or 'not found'}")
            all_active = False
    if not all_active:
        print("\n  Some connectors are not yet ACTIVE. They may still be provisioning.")
        print("  Re-run: python3 scripts/validate_pipeline.py")

    # Save config for ingest script
    stream_configs['_metadata'] = {
        'log_group_id': log_group_id,
        'la_namespace': la_namespace,
        'compartment_id': COMPARTMENT_ID
    }
    save_pipeline_config(stream_configs)

    print("\n" + "=" * 60)
    print("Pipeline Setup Complete!")
    print("=" * 60)
    print("\n  Architecture:")
    print("  Test Logs → OCI Streaming → Service Connector Hub → Log Analytics")
    print(f"\n  Streams created: {len(STREAMS)}")
    print(f"  Service Connectors: {len(STREAMS)}")
    print(f"  Log Group: {LOG_GROUP_NAME}")
    print("\n  Wait 2-3 minutes for Service Connectors to become ACTIVE,")
    print("  then run: python3 scripts/ingest_test_data.py")


if __name__ == "__main__":
    main()
