"""
Centralized OCI configuration, client factories, and validation for SOC detection scripts.

Config resolution order (highest priority first):
  1. Environment variables (OCI_TENANCY_ID, OCI_COMPARTMENT_ID, etc.)
  2. .env.local file in project root
  3. Hardcoded defaults below

Client factories defer `import oci` so offline scripts (convert_sigma.py,
generate_test_logs.py) can import constants without requiring the OCI SDK.
"""

import os
import re
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ─── .env.local loader (no python-dotenv dependency) ──────────

def _load_env_file(path):
    """Parse a KEY=VALUE file, ignoring comments and blank lines."""
    values = {}
    if not os.path.exists(path):
        return values
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            key, _, value = line.partition('=')
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            values[key] = value
    return values


_env_local = _load_env_file(os.path.join(PROJECT_DIR, '.env.local'))


def _cfg(env_key, default):
    """Resolve config: env var > .env.local > default."""
    return os.environ.get(env_key) or _env_local.get(env_key) or default


# ─── Configuration constants ──────────────────────────────────

TENANCY_ID = _cfg(
    "OCI_TENANCY_ID",
    "ocid1.tenancy.oc1..aaaaaaaaxzpxbcag7zgamh2erlggqro3y63tvm2rbkkjz4z2zskvagupiz7a",
)
COMPARTMENT_ID = _cfg(
    "OCI_COMPARTMENT_ID",
    "ocid1.compartment.oc1..aaaaaaaaghzlt3b6zl3nb7fsyh4nuiuzsuh4zzghfxmtfvvk4byylbvh56ba",
)
OCI_PROFILE = _cfg("OCI_PROFILE", "DEFAULT")
OCI_REGION = _cfg("OCI_REGION", "")

QUERIES_DIR = os.path.join(PROJECT_DIR, 'queries')
HUNTING_DIR = os.path.join(QUERIES_DIR, 'hunting')
TEST_DATA_DIR = os.path.join(PROJECT_DIR, 'test_data')

LOG_GROUP_NAME = "soc-detection-test-logs"
LOG_GROUP_DESC = "Log group for SOC detection rule test data"

CUSTOM_LOG_SOURCES = [
    "SOC Linux Syslog Logs",
    "SOC Windows Sysmon Logs",
    "SOC Cloud Guard Logs",
]

# Preferred-to-fallback source candidates by detection family.
# Order matters: first match wins for runtime source selection.
SOURCE_CANDIDATE_GROUPS = {
    "oci_audit": [
        "OCI Audit Logs",
    ],
    "cloud_guard": [
        "OCI Cloud Guard Problems",
        "OCI Cloud Guard Logs",
        "SOC Cloud Guard Logs",
    ],
    # No exact native equivalent covers all SOC Linux Syslog detection patterns.
    "linux_syslog": [
        "SOC Linux Syslog Logs",
        "Linux Secure Logs",
        "Linux Syslog Logs",
        "Linux Audit Logs",
    ],
    "windows_sysmon": [
        "Windows Sysmon Events",
        "Windows Sysmon Operational Logs",
        "SOC Windows Sysmon Logs",
    ],
    "windows_event_security": [
        "Windows Event Security Logs",
    ],
    "windows_event_system": [
        "Windows Event System Logs",
    ],
    "linux_secure": [
        "Linux Secure Logs",
    ],
    "sysmon_operational": [
        "Windows Sysmon Operational Logs",
        "Windows Sysmon Events",
        "SOC Windows Sysmon Logs",
    ],
}

TEST_DATA_FILES = [
    "oci_audit.jsonl",
    "cloud_guard.jsonl",
    "linux_syslog.jsonl",
    "windows_sysmon.jsonl",
    "windows_event_security.jsonl",
    "windows_event_system.jsonl",
    "linux_secure.jsonl",
    "sysmon_operational.jsonl",
]


# ─── OCI client factories (deferred import) ──────────────────

def get_oci_config():
    """Load and return the OCI SDK config dict."""
    import oci
    kwargs = {}
    if OCI_PROFILE:
        kwargs["profile_name"] = OCI_PROFILE
    config = oci.config.from_file(**kwargs)
    if OCI_REGION:
        config["region"] = OCI_REGION
    return config


def get_la_client():
    """Return an OCI Log Analytics client."""
    import oci
    return oci.log_analytics.LogAnalyticsClient(get_oci_config())


def get_dashboard_client():
    """Return an OCI Management Dashboard client."""
    import oci
    return oci.management_dashboard.DashxApisClient(get_oci_config())


def get_streaming_admin_client():
    """Return an OCI Streaming Admin client."""
    import oci
    return oci.streaming.StreamAdminClient(get_oci_config())


def get_sch_client():
    """Return an OCI Service Connector Hub client."""
    import oci
    return oci.sch.ServiceConnectorClient(get_oci_config())


# ─── Shared utilities ─────────────────────────────────────────

def get_namespace(la_client):
    """Discover the Log Analytics namespace for this tenancy."""
    namespaces = la_client.list_namespaces(compartment_id=TENANCY_ID).data
    if not namespaces.items:
        print("ERROR: No Log Analytics namespace found. Is Log Analytics enabled?")
        sys.exit(1)
    ns = namespaces.items[0].namespace_name
    print(f"  Namespace: {ns}")
    return ns


def ensure_log_group(la_client, namespace):
    """Find or create the SOC detection test log group."""
    import oci
    existing = la_client.list_log_analytics_log_groups(
        namespace_name=namespace,
        compartment_id=COMPARTMENT_ID,
    ).data.items

    for lg in existing:
        if lg.display_name == LOG_GROUP_NAME:
            print(f"  Log Group exists: {lg.display_name} ({lg.id})")
            return lg.id

    print(f"  Creating Log Group: {LOG_GROUP_NAME}")
    details = oci.log_analytics.models.CreateLogAnalyticsLogGroupDetails(
        display_name=LOG_GROUP_NAME,
        description=LOG_GROUP_DESC,
        compartment_id=COMPARTMENT_ID,
    )
    new_lg = la_client.create_log_analytics_log_group(
        namespace_name=namespace,
        create_log_analytics_log_group_details=details,
    ).data
    print(f"  Created Log Group: {new_lg.id}")
    return new_lg.id


def list_available_log_sources(la_client, namespace, compartment_id=COMPARTMENT_ID):
    """Return a set of available Log Analytics source display names."""
    sources = set()
    page = None
    while True:
        kwargs = {
            "limit": 1000,
            "is_system": "ALL",
        }
        if compartment_id:
            kwargs["compartment_id"] = compartment_id
        if page:
            kwargs["page"] = page

        resp = la_client.list_sources(namespace, **kwargs)
        for src in resp.data.items:
            if src.display_name:
                sources.add(src.display_name)
        page = resp.headers.get("opc-next-page")
        if not page:
            break
    return sources


def resolve_source_from_candidates(available_sources, candidates):
    """Pick the first source that exists from an ordered candidate list."""
    for candidate in candidates or []:
        if candidate in available_sources:
            return candidate
    return None


# ─── Validation functions ─────────────────────────────────────

_OCID_RE = re.compile(
    r'^ocid1\.[a-z]+\.oc[0-9]+\.[a-z0-9-]*\.[a-z0-9]{60}$'
)


def validate_ocid_format():
    """Check that TENANCY_ID and COMPARTMENT_ID look like valid OCIDs."""
    results = []
    for name, value in [("TENANCY_ID", TENANCY_ID), ("COMPARTMENT_ID", COMPARTMENT_ID)]:
        if _OCID_RE.match(value):
            results.append((name, True, value[:40] + "..."))
        else:
            results.append((name, False, f"invalid format: {value[:50]}"))
    return results


def validate_oci_cli_config():
    """Check that ~/.oci/config exists and the configured profile is present."""
    config_path = os.path.expanduser("~/.oci/config")
    if not os.path.exists(config_path):
        return [("~/.oci/config", False, "file not found")]

    profile_header = f"[{OCI_PROFILE}]"
    with open(config_path, 'r') as f:
        content = f.read()

    if profile_header in content:
        return [("~/.oci/config", True, f"profile [{OCI_PROFILE}] found")]
    return [("~/.oci/config", False, f"profile [{OCI_PROFILE}] not found")]


def validate_namespace():
    """Check that the Log Analytics namespace is discoverable (online)."""
    try:
        la_client = get_la_client()
        ns = la_client.list_namespaces(compartment_id=TENANCY_ID).data
        if ns.items:
            return [("LA Namespace", True, ns.items[0].namespace_name)]
        return [("LA Namespace", False, "no namespace found")]
    except Exception as e:
        return [("LA Namespace", False, str(e)[:100])]


def validate_compartment():
    """Check that the compartment is accessible via the Identity API (online)."""
    try:
        import oci
        identity = oci.identity.IdentityClient(get_oci_config())
        comp = identity.get_compartment(COMPARTMENT_ID).data
        return [("Compartment", True, comp.name)]
    except Exception as e:
        return [("Compartment", False, str(e)[:100])]


def validate_query_files():
    """Check that all query JSON files exist and contain a 'query' field."""
    import json
    results = []
    if not os.path.isdir(QUERIES_DIR):
        return [("queries/", False, "directory not found")]

    json_files = []
    for root, _, files in os.walk(QUERIES_DIR):
        for f in files:
            if f.endswith('.json') and f != 'manifest.json':
                json_files.append(os.path.join(root, f))

    if not json_files:
        return [("Query files", False, "no .json files found")]

    errors = 0
    for path in json_files:
        try:
            with open(path, 'r') as fh:
                data = json.load(fh)
            if 'query' not in data:
                errors += 1
                results.append((os.path.basename(path), False, "missing 'query' field"))
        except (json.JSONDecodeError, OSError) as e:
            errors += 1
            results.append((os.path.basename(path), False, str(e)[:80]))

    if errors == 0:
        results.insert(0, ("Query files", True, f"{len(json_files)} files OK"))
    else:
        results.insert(0, ("Query files", False, f"{errors}/{len(json_files)} files have errors"))
    return results


def validate_log_sources():
    """Check that at least one candidate source exists per detection family."""
    try:
        la_client = get_la_client()
        ns = la_client.list_namespaces(compartment_id=TENANCY_ID).data.items[0].namespace_name
        available = list_available_log_sources(la_client, ns, COMPARTMENT_ID)
        results = []

        for group_name, candidates in SOURCE_CANDIDATE_GROUPS.items():
            resolved = resolve_source_from_candidates(available, candidates)
            if resolved:
                results.append((group_name, True, f"using '{resolved}'"))
            else:
                results.append((group_name, False, f"none found from {candidates}"))
        return results
    except Exception as e:
        return [("Log Sources", False, str(e)[:100])]


def validate_test_data():
    """Check that the 4 NDJSON test data files are present."""
    results = []
    for filename in TEST_DATA_FILES:
        path = os.path.join(TEST_DATA_DIR, filename)
        if os.path.exists(path):
            size = os.path.getsize(path)
            results.append((filename, True, f"{size} bytes"))
        else:
            results.append((filename, False, "not found"))
    return results


# ─── Validation orchestrator ──────────────────────────────────

_VALIDATORS = {
    'ocid': ('OCID Format', validate_ocid_format),
    'cli': ('OCI CLI Config', validate_oci_cli_config),
    'namespace': ('LA Namespace', validate_namespace),
    'compartment': ('Compartment Access', validate_compartment),
    'query_files': ('Query Files', validate_query_files),
    'log_sources': ('Log Sources', validate_log_sources),
    'test_data': ('Test Data', validate_test_data),
}


def validate_oci_setup(checks=None):
    """Run selected validation checks and print results.

    Args:
        checks: list of check names (keys from _VALIDATORS), or None for all offline checks.

    Returns:
        True if all checks passed, False otherwise.
    """
    if checks is None:
        checks = ['ocid', 'cli']

    all_ok = True
    print("\n" + "=" * 60)
    print("  Pre-flight Validation")
    print("=" * 60)

    for check_name in checks:
        if check_name not in _VALIDATORS:
            print(f"\n  ? Unknown check: {check_name}")
            continue

        label, validator = _VALIDATORS[check_name]
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
