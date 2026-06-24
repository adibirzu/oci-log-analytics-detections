"""Validation orchestration for OCI SOC detection configuration."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any


def build_validators(module_globals: dict[str, Any]) -> tuple[Callable, ...]:
    """Build validator callables bound to ``oci_config`` module globals."""

    def validate_ocid_format():
        results = []
        checks = [
            ("TENANCY_ID", module_globals["resolve_tenancy_id"]()),
            ("COMPARTMENT_ID", module_globals["resolve_compartment_id"]()),
        ]
        if module_globals["LOG_GROUP_ID"]:
            checks.append(("LOG_GROUP_ID", module_globals["LOG_GROUP_ID"]))
        for name, value in checks:
            if not value:
                results.append((name, False, "not set"))
            elif module_globals["_OCID_RE"].match(value):
                results.append((name, True, value[:40] + "..."))
            else:
                results.append((name, False, f"invalid format: {value[:50]}"))
        return results

    def validate_oci_cli_config():
        if os.environ.get("OCI_RESOURCE_PRINCIPAL_VERSION"):
            return [("OCI Auth", True, "Resource Principal")]

        auth_mode = os.environ.get("OCI_AUTH_MODE", "").lower().replace("-", "_")
        if auth_mode in ("instance_principal", "instanceprincipal"):
            return [("OCI Auth", True, "Instance Principal")]

        if os.environ.get("OCI_KEY_FILE") or os.environ.get("OCI_KEY_CONTENT"):
            return [("OCI Auth", True, "Environment variables (OCI_KEY_FILE/OCI_KEY_CONTENT)")]

        config_path = os.path.expanduser("~/.oci/config")
        if not os.path.exists(config_path):
            return [("~/.oci/config", False, "file not found (set OCI_AUTH_MODE=instance_principal for VM/Docker)")]

        profile_header = f"[{module_globals['OCI_PROFILE']}]"
        with open(config_path, "r") as handle:
            content = handle.read()

        if profile_header in content:
            return [("~/.oci/config", True, f"profile [{module_globals['OCI_PROFILE']}] found")]
        return [("~/.oci/config", False, f"profile [{module_globals['OCI_PROFILE']}] not found")]

    def validate_namespace():
        try:
            la_client = module_globals["get_la_client"]()
            tenancy = module_globals["resolve_tenancy_id"]()
            if not tenancy:
                return [("LA Namespace", False, "tenancy unresolved")]
            namespaces = la_client.list_namespaces(compartment_id=tenancy).data
            if namespaces.items:
                return [("LA Namespace", True, namespaces.items[0].namespace_name)]
            return [("LA Namespace", False, "no namespace found")]
        except Exception as exc:
            return [("LA Namespace", False, str(exc)[:100])]

    def validate_compartment():
        try:
            import oci

            identity = module_globals["_get_client"](oci.identity.IdentityClient)
            compartment = identity.get_compartment(module_globals["resolve_compartment_id"]()).data
            return [("Compartment", True, compartment.name)]
        except Exception as exc:
            return [("Compartment", False, str(exc)[:100])]

    def validate_query_files():
        results = []
        queries_dir = module_globals["QUERIES_DIR"]
        if not os.path.isdir(queries_dir):
            return [("queries/", False, "directory not found")]

        json_files = []
        excluded = module_globals["GENERATED_QUERY_ARTIFACT_FILENAMES"]
        for root, _, files in os.walk(queries_dir):
            for filename in files:
                if filename.endswith(".json") and filename not in excluded:
                    json_files.append(os.path.join(root, filename))

        if not json_files:
            return [("Query files", False, "no .json files found")]

        errors = 0
        for path in json_files:
            try:
                with open(path, "r") as handle:
                    data = json.load(handle)
                if "query" not in data:
                    errors += 1
                    results.append((os.path.basename(path), False, "missing 'query' field"))
            except (json.JSONDecodeError, OSError) as exc:
                errors += 1
                results.append((os.path.basename(path), False, str(exc)[:80]))

        if errors == 0:
            results.insert(0, ("Query files", True, f"{len(json_files)} files OK"))
        else:
            results.insert(0, ("Query files", False, f"{errors}/{len(json_files)} files have errors"))
        return results

    def validate_log_sources():
        try:
            la_client = module_globals["get_la_client"]()
            tenancy = module_globals["resolve_tenancy_id"]()
            namespace = la_client.list_namespaces(compartment_id=tenancy).data.items[0].namespace_name
            available = module_globals["list_available_log_sources"](
                la_client,
                namespace,
                module_globals["resolve_compartment_id"](),
            )
            results = []

            for group_name, candidates in module_globals["SOURCE_CANDIDATE_GROUPS"].items():
                resolved = module_globals["resolve_source_from_candidates"](available, candidates)
                if resolved:
                    results.append((group_name, True, f"using '{resolved}'"))
                else:
                    results.append((group_name, False, f"none found from {candidates}"))
            return results
        except Exception as exc:
            return [("Log Sources", False, str(exc)[:100])]

    def validate_test_data():
        results = []
        for filename in module_globals["TEST_DATA_FILES"]:
            path = os.path.join(module_globals["TEST_DATA_DIR"], filename)
            if os.path.exists(path):
                size = os.path.getsize(path)
                results.append((filename, True, f"{size} bytes"))
            else:
                results.append((filename, False, "not found"))
        return results

    def validate_log_group():
        log_group_id = module_globals["LOG_GROUP_ID"]
        if not log_group_id:
            return [("Log Group", False, "LOG_ANALYTICS_LOG_GROUP_ID / LA_LOG_GROUP_ID not set")]
        try:
            la_client = module_globals["get_la_client"]()
            get_namespace = module_globals["get_namespace"]
            namespace = get_namespace.__wrapped__(la_client) if hasattr(get_namespace, "__wrapped__") else (
                module_globals["LA_NAMESPACE"]
                or la_client.list_namespaces(
                    compartment_id=module_globals["resolve_tenancy_id"]()
                ).data.items[0].namespace_name
            )
            log_group = la_client.get_log_analytics_log_group(
                namespace_name=namespace,
                log_analytics_log_group_id=log_group_id,
            ).data
            return [("Log Group", True, f"{log_group.display_name} ({log_group_id[:40]}...)")]
        except Exception as exc:
            return [("Log Group", False, f"{log_group_id[:40]}... — {str(exc)[:60]}")]

    def validate_streams():
        expected_names = module_globals["get_expected_stream_names"]()
        try:
            stream_admin = module_globals["get_streaming_admin_client"]()
            compartment_id = module_globals["resolve_compartment_id"]()
            results = []
            for name in expected_names:
                streams = stream_admin.list_streams(
                    compartment_id=compartment_id,
                    name=name,
                    lifecycle_state="ACTIVE",
                ).data
                if streams:
                    results.append((name, True, f"ACTIVE ({streams[0].id[:40]}...)"))
                else:
                    results.append((name, False, "not found or not ACTIVE"))
            return results
        except Exception as exc:
            return [("Streams", False, str(exc)[:100])]

    def validate_service_connectors():
        expected_prefixes = module_globals["get_expected_connector_names"]()
        try:
            service_connector = module_globals["get_sch_client"]()
            compartment_id = module_globals["resolve_compartment_id"]()
            results = []
            for name in expected_prefixes:
                connectors = service_connector.list_service_connectors(
                    compartment_id=compartment_id,
                    display_name=name,
                ).data.items
                active = [
                    connector
                    for connector in connectors
                    if getattr(connector, "lifecycle_state", "") == "ACTIVE"
                ]
                if active:
                    results.append((name, True, f"ACTIVE ({active[0].id[:40]}...)"))
                else:
                    results.append((name, False, "not found or not ACTIVE"))
            return results
        except Exception as exc:
            return [("Service Connectors", False, str(exc)[:100])]

    def validate_streaming_config():
        config_path = os.path.join(module_globals["PROJECT_DIR"], "config", "streaming_config.json")
        if not os.path.exists(config_path):
            return [("streaming_config.json", False, "file not found")]

        try:
            with open(config_path) as handle:
                config = json.load(handle)
        except (json.JSONDecodeError, OSError) as exc:
            return [("streaming_config.json", False, str(exc)[:80])]

        results = []
        meta = config.get("_metadata", {})

        config_log_group = meta.get("log_group_id", "")
        log_group_id = module_globals["LOG_GROUP_ID"]
        if log_group_id and config_log_group and config_log_group != log_group_id:
            results.append(("log_group_id", False, f"MISMATCH: config={config_log_group[-12:]} vs env={log_group_id[-12:]}"))
        elif config_log_group:
            results.append(("log_group_id", True, f"...{config_log_group[-12:]}"))
        else:
            results.append(("log_group_id", False, "not set in config"))

        config_compartment = meta.get("compartment_id", "")
        active_compartment = module_globals["resolve_compartment_id"]()
        if active_compartment and config_compartment and config_compartment != active_compartment:
            results.append(("compartment_id", False, f"MISMATCH: config={config_compartment[-12:]} vs env={active_compartment[-12:]}"))
        elif config_compartment:
            results.append(("compartment_id", True, f"...{config_compartment[-12:]}"))

        config_namespace = meta.get("la_namespace", "")
        namespace = module_globals["LA_NAMESPACE"]
        if namespace and config_namespace and config_namespace != namespace:
            results.append(("la_namespace", False, f"MISMATCH: config={config_namespace} vs env={namespace}"))
        elif config_namespace:
            results.append(("la_namespace", True, config_namespace))

        stream_count = sum(1 for key in config if key != "_metadata")
        expected_stream_count = len(module_globals["get_expected_stream_names"](config))
        results.append((
            "streams",
            stream_count >= expected_stream_count,
            f"{stream_count} stream(s) configured, expecting {expected_stream_count}",
        ))

        return results

    validators = {
        "ocid": ("OCID Format", validate_ocid_format),
        "cli": ("OCI CLI Config", validate_oci_cli_config),
        "namespace": ("LA Namespace", validate_namespace),
        "compartment": ("Compartment Access", validate_compartment),
        "query_files": ("Query Files", validate_query_files),
        "log_sources": ("Log Sources", validate_log_sources),
        "test_data": ("Test Data", validate_test_data),
        "log_group": ("Log Group", validate_log_group),
        "streams": ("Streams", validate_streams),
        "service_connectors": ("Service Connectors", validate_service_connectors),
        "streaming_config": ("Streaming Config", validate_streaming_config),
    }

    def validate_oci_setup(checks=None):
        if checks is None:
            checks = ["ocid", "cli"]

        all_ok = True
        print("\n" + "=" * 60)
        print("  Pre-flight Validation")
        print("=" * 60)

        for check_name in checks:
            if check_name not in validators:
                print(f"\n  ? Unknown check: {check_name}")
                continue

            label, validator = validators[check_name]
            print(f"\n  [{label}]")
            results = validator()
            for name, ok, detail in results:
                icon = "OK" if ok else "FAIL"
                print(f"    [{icon:4s}] {name}: {detail}")
                if not ok:
                    all_ok = False

        print(f"\n{'=' * 60}")
        if all_ok:
            print("  All checks passed.")
        else:
            print("  Some checks FAILED. Fix issues above before proceeding.")
        print(f"{'=' * 60}\n")
        return all_ok

    return (
        validate_ocid_format,
        validate_oci_cli_config,
        validate_namespace,
        validate_compartment,
        validate_query_files,
        validate_log_sources,
        validate_test_data,
        validate_log_group,
        validate_streams,
        validate_service_connectors,
        validate_streaming_config,
        validators,
        validate_oci_setup,
    )

