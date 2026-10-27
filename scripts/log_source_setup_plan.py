"""Pure dry-run selection and rendering for the log-source setup CLI."""
from logsources.definitions import *  # noqa: F401,F403
from logsources.field_helpers import select_field_contract, unique_preserving_order


def build_dry_run_plan(*, octo_apm_only=False, application_only=False, windows_access_only=False):
    """Return the complete public plan without discovering or constructing OCI clients."""
    application_only = application_only or octo_apm_only
    windows_access_fields = unique_preserving_order(
        name for name, _path, _sequence in WINSEC_FIELD_MAPPINGS + WINSYS_FIELD_MAPPINGS
        if name in CUSTOM_FIELDS
    )
    lines = []
    fields_to_create, field_mappings = select_field_contract(
        octo_apm_only=octo_apm_only,
        application_only=application_only,
    )
    if windows_access_only:
        fields_to_create = windows_access_fields
    elif not application_only:
        field_mappings = []
    lines.append("DRY RUN - would create:")
    lines.append(f"  up to {len(unique_preserving_order(fields_to_create))} custom fields")
    lines.append("  existing namespace fields are reused by exact display name")
    lines.append("  run with --field-audit to inspect live reuse before creating fields")
    if windows_access_only:
        lines.append("  2 JSON parsers for deterministic Security/System synthetic upload validation")
        lines.append(f"  1 log source: {WINSEC_SOURCE_DISPLAY} ({WINSEC_SOURCE_INTERNAL})")
        lines.append(f"  1 log source: {WINSYS_SOURCE_DISPLAY} ({WINSYS_SOURCE_INTERNAL})")
        lines.append("  Application-channel fixtures are validated locally; optional upload reuses an existing SOC Application Logs source")
        lines.append("  continuous collection reuses Oracle-defined Windows Security/System/Application Events sources")
        return "\n".join(lines) + "\n"
    if application_only:
        lines.append(f"  1 JSON parser: {APP_PARSER_DISPLAY} ({len(field_mappings)} field maps)")
        lines.append(f"  1 log source: {APP_SOURCE_DISPLAY} ({APP_SOURCE_INTERNAL})")
        return "\n".join(lines) + "\n"
    lines.append(f"  19 JSON parsers")
    lines.append(f"  up to 21 log sources (SOC sources skipped when native equivalent exists):")
    lines.append(f"    - {LINUX_SOURCE_DISPLAY} ({LINUX_SOURCE_INTERNAL})")
    lines.append(f"    - {WINDOWS_SOURCE_DISPLAY} ({WINDOWS_SOURCE_INTERNAL})")
    lines.append(f"    - {CG_SOURCE_DISPLAY} ({CG_SOURCE_INTERNAL})")
    lines.append(f"    - {CGIS_SOURCE_DISPLAY} ({CGIS_SOURCE_INTERNAL})")
    lines.append(f"    - {OSQUERY_SOURCE_DISPLAY} ({OSQUERY_SOURCE_INTERNAL})")
    lines.append(f"    - {WINSEC_SOURCE_DISPLAY} ({WINSEC_SOURCE_INTERNAL})")
    lines.append(f"    - {WINSYS_SOURCE_DISPLAY} ({WINSYS_SOURCE_INTERNAL})")
    lines.append(f"    - {WINPS_SOURCE_DISPLAY} ({WINPS_SOURCE_INTERNAL})")
    lines.append(f"    - {WINDEF_SOURCE_DISPLAY} ({WINDEF_SOURCE_INTERNAL})")
    lines.append(f"    - {LINSEC_SOURCE_DISPLAY} ({LINSEC_SOURCE_INTERNAL})")
    lines.append(f"    - {SYSMON_SOURCE_DISPLAY} ({SYSMON_SOURCE_INTERNAL})")
    lines.append(f"    - {SYSNET_SOURCE_DISPLAY} ({SYSNET_SOURCE_INTERNAL})")
    lines.append(f"    - {WAF_SOURCE_DISPLAY} ({WAF_SOURCE_INTERNAL})")
    lines.append(f"    - {LB_SOURCE_DISPLAY} ({LB_SOURCE_INTERNAL})")
    lines.append(f"    - {WEBAPP_SOURCE_DISPLAY} ({WEBAPP_SOURCE_INTERNAL})")
    lines.append(f"    - {APP_SOURCE_DISPLAY} ({APP_SOURCE_INTERNAL})")
    lines.append(f"    - {GENAI_SOURCE_DISPLAY} ({GENAI_SOURCE_INTERNAL})")
    lines.append(f"    - {AZURE_CUSTOM_SOURCE_DISPLAY} ({AZURE_CUSTOM_SOURCE_INTERNAL})")
    lines.append(f"    - {VCN_SOURCE_DISPLAY} ({VCN_SOURCE_INTERNAL})")
    lines.append(f"    - {FW_SOURCE_DISPLAY} ({FW_SOURCE_INTERNAL})")
    lines.append(f"    - {HEALTH_SOURCE_DISPLAY} ({HEALTH_SOURCE_INTERNAL})")
    for _wz_internal, _wz_display, _wz_desc, _wz_parser in WAZUH_SOURCE_SPECS:
        lines.append(f"    - {_wz_display} ({_wz_internal})")
    return "\n".join(lines) + "\n"