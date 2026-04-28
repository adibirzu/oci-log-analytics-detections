"""
Centralized OCI configuration, client factories, and validation for SOC detection scripts.

Config resolution order (highest priority first):
  1. Environment variables (OCI_TENANCY_ID, OCI_COMPARTMENT_ID, etc.)
  2. .env.local file in project root
  3. Empty string (no hardcoded defaults — use require_oci_config() to guard API calls)

Client factories defer `import oci` so offline scripts (convert_sigma.py,
generate_test_logs.py) can import constants without requiring the OCI SDK.
"""

import os
import re
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STREAMING_CONFIG_PATH = os.path.join(PROJECT_DIR, 'config', 'streaming_config.json')

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

TENANCY_ID = _cfg("OCI_TENANCY_ID", "") or _cfg("OCI_TENANCY_OCID", "")
COMPARTMENT_ID = (
    _cfg("OCI_COMPARTMENT_ID", "")  # MAIN demo-observability (set in .env.local)
    or _cfg("COMP_OBSERVABILITY", "")  # fallback
)
OCI_PROFILE = _cfg("OCI_PROFILE", "") or _cfg("OCI_CONFIG_PROFILE", "DEFAULT")
OCI_REGION = _cfg("OCI_REGION", "")

# Log Analytics identifiers — honour values set by upstream provisioning (OCI-DEMO)
LOG_GROUP_ID = _cfg("LOG_ANALYTICS_LOG_GROUP_ID", "") or _cfg("LA_LOG_GROUP_ID", "")
LA_NAMESPACE = _cfg("LA_NAMESPACE", "")

QUERIES_DIR = os.path.join(PROJECT_DIR, 'queries')
HUNTING_DIR = os.path.join(QUERIES_DIR, 'hunting')
APPS_DIR = os.path.join(QUERIES_DIR, 'apps')
TEST_DATA_DIR = os.path.join(PROJECT_DIR, 'test_data')

LOG_GROUP_NAME = "soc-detection-test-logs"
LOG_GROUP_DESC = "Log group for SOC detection rule test data"

CUSTOM_LOG_SOURCES = [
    "SOC Linux Syslog Logs",
    "SOC Windows Sysmon Logs",
    "SOC Sysmon Network Logs",
    "SOC Cloud Guard Logs",
    "SOC Application Logs",
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
    # SOC source first: native sources use XML parsers that can't parse JSON uploads
    "windows_sysmon": [
        "SOC Windows Sysmon Logs",
        "Windows Sysmon Events",
        "Windows Sysmon Operational Logs",
    ],
    "windows_event_security": [
        "Windows Event Security Logs",
        "Windows Security Events",
    ],
    "windows_event_system": [
        "Windows Event System Logs",
    ],
    "linux_secure": [
        "Linux Secure Logs",
    ],
    # SOC source first: native sources use XML parsers that can't parse JSON uploads
    "sysmon_operational": [
        "Windows Sysmon Operational Logs",
        "SOC Windows Sysmon Logs",
        "Windows Sysmon Events",
    ],
    # Network connection events require a parser that maps Event ID 3 fields.
    "sysmon_network": [
        "SOC Sysmon Network Logs",
        "Windows Sysmon Operational Logs",
        "Windows Sysmon Events",
    ],
    "waf_security": [
        "SOC WAF Security Logs",
        "OCI WAF Logs",
    ],
    "lb_access": [
        "SOC Load Balancer Access Logs",
        "OCI Load Balancer Access Logs",
    ],
    "webapp_security": [
        "SOC Web Application Logs",
    ],
    "application_logs": [
        "SOC Application Logs",
    ],
    "multicloud_health": [
        "SOC Multicloud Health Logs",
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
    "sysmon_network.jsonl",
    "waf_security.jsonl",
    "lb_access.jsonl",
    "webapp_security.jsonl",
    "application_logs.jsonl",
    "multicloud_health.jsonl",
]

CORE_SOC_STREAMS = [
    "soc-detection-oci-audit",
    "soc-detection-cloud-guard",
    "soc-detection-linux-audit",
    "soc-detection-windows-sysmon",
]


def load_streaming_config(config_path=STREAMING_CONFIG_PATH):
    """Load ``streaming_config.json`` if present, else return an empty dict."""
    import json

    if not os.path.exists(config_path):
        return {}

    try:
        with open(config_path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def get_expected_stream_names(streaming_config=None, config_path=STREAMING_CONFIG_PATH):
    """Return the core SOC streams plus any configured SOC extras.

    The first four streams are the required detection pipeline. Additional
    ``soc-detection-*`` entries in ``streaming_config.json`` are treated as
    extra runtime expectations, for example ``soc-detection-multicloud-health``.
    """
    if streaming_config is None:
        streaming_config = load_streaming_config(config_path)

    configured = [
        name for name in streaming_config
        if name != "_metadata" and name.startswith("soc-detection-")
    ]
    extras = [name for name in configured if name not in CORE_SOC_STREAMS]
    return CORE_SOC_STREAMS + extras


def get_expected_connector_names(streaming_config=None, config_path=STREAMING_CONFIG_PATH):
    """Return the expected SCH connector names for the SOC pipeline."""
    return [f"sch-{stream_name}-to-la" for stream_name in get_expected_stream_names(
        streaming_config=streaming_config,
        config_path=config_path,
    )]


def require_oci_config():
    """Verify that essential OCI identifiers are set. Call before any API access.

    Raises SystemExit with a descriptive message if TENANCY_ID or COMPARTMENT_ID
    is empty.  NOT called at import time so offline scripts still work.
    """
    missing = []
    if not TENANCY_ID:
        missing.append("TENANCY_ID (set OCI_TENANCY_ID or OCI_TENANCY_OCID)")
    if not COMPARTMENT_ID:
        missing.append("COMPARTMENT_ID (set OCI_COMPARTMENT_ID or COMP_OBSERVABILITY)")
    if missing:
        print("ERROR: Required OCI configuration is missing:")
        for m in missing:
            print(f"  - {m}")
        print("\nSet these in .env.local or as environment variables.")
        sys.exit(1)


# ─── OCI client factories (deferred import) ──────────────────

def _get_client(client_class, **extra_kwargs):
    """Create OCI SDK client with 4-tier auth fallback.

    1. Resource Principal (OCI_RESOURCE_PRINCIPAL_VERSION set)
    2. Instance Principal (OCI_AUTH_MODE=instance_principal)
    3. OCI config file (~/.oci/config)
    4. Environment variables (OCI_KEY_FILE/OCI_KEY_CONTENT)
    """
    import oci
    client_name = client_class.__name__
    auth_mode = os.environ.get("OCI_AUTH_MODE", "").lower().replace("-", "_")

    # 1. Resource Principal
    if os.environ.get("OCI_RESOURCE_PRINCIPAL_VERSION"):
        try:
            signer = oci.auth.signers.get_resource_principals_signer()
            return client_class({}, signer=signer, **extra_kwargs)
        except Exception:
            pass

    # 2. Instance Principal
    if auth_mode in ("instance_principal", "instanceprincipal", "auto"):
        try:
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            return client_class({}, signer=signer, **extra_kwargs)
        except Exception:
            pass

    # 3. OCI config file
    try:
        config = get_oci_config()
        return client_class(config, **extra_kwargs)
    except Exception:
        pass

    # 4. Environment variables
    key_file = os.environ.get("OCI_KEY_FILE")
    key_content = os.environ.get("OCI_KEY_CONTENT")
    if key_file or key_content:
        try:
            if key_file:
                with open(os.path.expanduser(key_file)) as f:
                    key_pem = f.read()
            else:
                key_pem = key_content.replace("\\n", "\n")
            config = {
                "user": os.environ["OCI_USER_OCID"],
                "key_content": key_pem,
                "fingerprint": os.environ["OCI_FINGERPRINT"],
                "tenancy": os.environ["OCI_TENANCY_OCID"],
                "region": os.environ.get("OCI_REGION", ""),
                "pass_phrase": os.environ.get("OCI_KEY_PASSPHRASE", ""),
            }
            return client_class(config, **extra_kwargs)
        except Exception:
            pass

    raise RuntimeError(f"No OCI auth method succeeded for {client_name}")


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


def get_la_client(timeout=None):
    """Return an OCI Log Analytics client."""
    import oci
    kwargs = {"timeout": timeout} if timeout is not None else {}
    return _get_client(oci.log_analytics.LogAnalyticsClient, **kwargs)


def get_dashboard_client():
    """Return an OCI Management Dashboard client."""
    import oci
    return _get_client(oci.management_dashboard.DashxApisClient)


def get_streaming_admin_client():
    """Return an OCI Streaming Admin client."""
    import oci
    return _get_client(oci.streaming.StreamAdminClient)


def get_sch_client():
    """Return an OCI Service Connector Hub client."""
    import oci
    return _get_client(oci.sch.ServiceConnectorClient)


# ─── Shared utilities ─────────────────────────────────────────

def get_namespace(la_client):
    """Return the Log Analytics namespace, using LA_NAMESPACE env var if set."""
    if LA_NAMESPACE:
        print(f"  Namespace (from env): {LA_NAMESPACE}")
        return LA_NAMESPACE
    namespaces = la_client.list_namespaces(compartment_id=TENANCY_ID).data
    if not namespaces.items:
        print("ERROR: No Log Analytics namespace found. Is Log Analytics enabled?")
        sys.exit(1)
    ns = namespaces.items[0].namespace_name
    print(f"  Namespace: {ns}")
    return ns


def ensure_log_group(la_client, namespace):
    """Find or create the SOC detection test log group.

    Resolution priority:
      1. LOG_GROUP_ID env var — verify it exists via API
      2. Search by LOG_GROUP_NAME in the compartment
      3. Create a new log group
    """
    import oci

    # Priority 1: use LOG_GROUP_ID from env if set
    if LOG_GROUP_ID:
        try:
            lg = la_client.get_log_analytics_log_group(
                namespace_name=namespace,
                log_analytics_log_group_id=LOG_GROUP_ID,
            ).data
            print(f"  Log Group (from env): {lg.display_name} ({lg.id})")
            return lg.id
        except oci.exceptions.ServiceError as e:
            print(f"  WARNING: LOG_GROUP_ID from env not accessible ({e.status}): {LOG_GROUP_ID}")
            print("  Falling back to name-based search...")

    # Priority 2: search by name
    existing = la_client.list_log_analytics_log_groups(
        namespace_name=namespace,
        compartment_id=COMPARTMENT_ID,
    ).data.items

    for lg in existing:
        if lg.display_name == LOG_GROUP_NAME:
            print(f"  Log Group exists: {lg.display_name} ({lg.id})")
            if LOG_GROUP_ID and lg.id != LOG_GROUP_ID:
                print(f"  WARNING: Found log group differs from LOG_GROUP_ID env var!")
                print(f"    env:   {LOG_GROUP_ID}")
                print(f"    found: {lg.id}")
            return lg.id

    # Priority 3: create new
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
    """Check that TENANCY_ID, COMPARTMENT_ID, and LOG_GROUP_ID look like valid OCIDs."""
    results = []
    checks = [("TENANCY_ID", TENANCY_ID), ("COMPARTMENT_ID", COMPARTMENT_ID)]
    if LOG_GROUP_ID:
        checks.append(("LOG_GROUP_ID", LOG_GROUP_ID))
    for name, value in checks:
        if not value:
            results.append((name, False, "not set"))
        elif _OCID_RE.match(value):
            results.append((name, True, value[:40] + "..."))
        else:
            results.append((name, False, f"invalid format: {value[:50]}"))
    return results


def validate_oci_cli_config():
    """Check that OCI auth is available (signer-based or config file)."""
    # Signer-based auth doesn't need ~/.oci/config
    if os.environ.get("OCI_RESOURCE_PRINCIPAL_VERSION"):
        return [("OCI Auth", True, "Resource Principal")]

    auth_mode = os.environ.get("OCI_AUTH_MODE", "").lower().replace("-", "_")
    if auth_mode in ("instance_principal", "instanceprincipal"):
        return [("OCI Auth", True, "Instance Principal")]

    # Check for env var auth
    if os.environ.get("OCI_KEY_FILE") or os.environ.get("OCI_KEY_CONTENT"):
        return [("OCI Auth", True, "Environment variables (OCI_KEY_FILE/OCI_KEY_CONTENT)")]

    # Fall back to config file check
    config_path = os.path.expanduser("~/.oci/config")
    if not os.path.exists(config_path):
        return [("~/.oci/config", False, "file not found (set OCI_AUTH_MODE=instance_principal for VM/Docker)")]

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
        identity = _get_client(oci.identity.IdentityClient)
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
            if f.endswith('.json') and f not in ('manifest.json', 'catalog.json', 'dashboard_inventory.json'):
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
    """Check that the configured NDJSON test data files are present."""
    results = []
    for filename in TEST_DATA_FILES:
        path = os.path.join(TEST_DATA_DIR, filename)
        if os.path.exists(path):
            size = os.path.getsize(path)
            results.append((filename, True, f"{size} bytes"))
        else:
            results.append((filename, False, "not found"))
    return results


def validate_log_group():
    """Check that the target log group is accessible (online)."""
    if not LOG_GROUP_ID:
        return [("Log Group", False, "LOG_ANALYTICS_LOG_GROUP_ID / LA_LOG_GROUP_ID not set")]
    try:
        la_client = get_la_client()
        ns = get_namespace.__wrapped__(la_client) if hasattr(get_namespace, '__wrapped__') else (
            LA_NAMESPACE or la_client.list_namespaces(compartment_id=TENANCY_ID).data.items[0].namespace_name
        )
        lg = la_client.get_log_analytics_log_group(
            namespace_name=ns,
            log_analytics_log_group_id=LOG_GROUP_ID,
        ).data
        return [("Log Group", True, f"{lg.display_name} ({LOG_GROUP_ID[:40]}...)")]
    except Exception as e:
        return [("Log Group", False, f"{LOG_GROUP_ID[:40]}... — {str(e)[:60]}")]


def validate_streams():
    """Check that the expected SOC detection streams are ACTIVE (online)."""
    expected_names = get_expected_stream_names()
    try:
        stream_admin = get_streaming_admin_client()
        results = []
        for name in expected_names:
            streams = stream_admin.list_streams(
                compartment_id=COMPARTMENT_ID, name=name, lifecycle_state="ACTIVE"
            ).data
            if streams:
                results.append((name, True, f"ACTIVE ({streams[0].id[:40]}...)"))
            else:
                results.append((name, False, "not found or not ACTIVE"))
        return results
    except Exception as e:
        return [("Streams", False, str(e)[:100])]


def validate_service_connectors():
    """Check that the expected SCH connectors are ACTIVE (online)."""
    expected_prefixes = get_expected_connector_names()
    try:
        sch = get_sch_client()
        results = []
        for name in expected_prefixes:
            connectors = sch.list_service_connectors(
                compartment_id=COMPARTMENT_ID, display_name=name
            ).data.items
            active = [c for c in connectors if getattr(c, "lifecycle_state", "") == "ACTIVE"]
            if active:
                results.append((name, True, f"ACTIVE ({active[0].id[:40]}...)"))
            else:
                results.append((name, False, "not found or not ACTIVE"))
        return results
    except Exception as e:
        return [("Service Connectors", False, str(e)[:100])]


def validate_streaming_config():
    """Check consistency between streaming_config.json and env vars (offline)."""
    import json
    config_path = os.path.join(PROJECT_DIR, 'config', 'streaming_config.json')
    if not os.path.exists(config_path):
        return [("streaming_config.json", False, "file not found")]

    try:
        with open(config_path) as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return [("streaming_config.json", False, str(e)[:80])]

    results = []
    meta = cfg.get("_metadata", {})

    # Check log group ID consistency
    cfg_lg = meta.get("log_group_id", "")
    if LOG_GROUP_ID and cfg_lg and cfg_lg != LOG_GROUP_ID:
        results.append(("log_group_id", False,
                         f"MISMATCH: config={cfg_lg[-12:]} vs env={LOG_GROUP_ID[-12:]}"))
    elif cfg_lg:
        results.append(("log_group_id", True, f"...{cfg_lg[-12:]}"))
    else:
        results.append(("log_group_id", False, "not set in config"))

    # Check compartment consistency
    cfg_comp = meta.get("compartment_id", "")
    if COMPARTMENT_ID and cfg_comp and cfg_comp != COMPARTMENT_ID:
        results.append(("compartment_id", False,
                         f"MISMATCH: config={cfg_comp[-12:]} vs env={COMPARTMENT_ID[-12:]}"))
    elif cfg_comp:
        results.append(("compartment_id", True, f"...{cfg_comp[-12:]}"))

    # Check namespace consistency
    cfg_ns = meta.get("la_namespace", "")
    if LA_NAMESPACE and cfg_ns and cfg_ns != LA_NAMESPACE:
        results.append(("la_namespace", False,
                         f"MISMATCH: config={cfg_ns} vs env={LA_NAMESPACE}"))
    elif cfg_ns:
        results.append(("la_namespace", True, cfg_ns))

    # Check stream entries
    stream_count = sum(1 for k in cfg if k != "_metadata")
    expected_stream_count = len(get_expected_stream_names(cfg))
    results.append(("streams", True if stream_count >= expected_stream_count else False,
                     f"{stream_count} stream(s) configured, expecting {expected_stream_count}"))

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
    'log_group': ('Log Group', validate_log_group),
    'streams': ('Streams', validate_streams),
    'service_connectors': ('Service Connectors', validate_service_connectors),
    'streaming_config': ('Streaming Config', validate_streaming_config),
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
