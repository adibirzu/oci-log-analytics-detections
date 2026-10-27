"""Dashboard catalog facade and deterministic Sentinel group loader.

Auto-extracted from deploy_dashboard.py (behavior-preserving). Pure data plus the
deterministic Sentinel-group loader; no OCI client calls at import beyond reading
local query JSON. Declared dashboard data lives in ``dashboards.definitions``.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from oci_config import QUERIES_DIR


from dashboards.definitions import (
    DASHBOARDS, OCTO_APM_WORKSHOP_TIME_SELECTION, octo_apm_workshop_widget,
)


SENTINEL_DASHBOARD_GROUPS = {
    "identity": "SOC: Microsoft Sentinel Identity Converted Detections",
    "endpoint": "SOC: Microsoft Sentinel Endpoint Converted Detections",
    "azure_cloud": "SOC: Microsoft Sentinel Azure Cloud Converted Detections",
    "m365": "SOC: Microsoft Sentinel M365 Converted Detections",
    "network": "SOC: Microsoft Sentinel Network Converted Detections",
}


SENTINEL_DASHBOARD_DESCRIPTIONS = {
    "identity": "Live-validated Microsoft Sentinel identity detections converted to OCI Log Analytics Logan QL.",
    "endpoint": "Live-validated Microsoft Sentinel endpoint detections converted to OCI Log Analytics Logan QL.",
    "azure_cloud": "Live-validated Microsoft Sentinel Azure cloud detections converted to OCI Log Analytics Logan QL.",
    "m365": "Live-validated Microsoft Sentinel Microsoft 365 detections converted to OCI Log Analytics Logan QL.",
    "network": "Live-validated Microsoft Sentinel network detections converted to OCI Log Analytics Logan QL.",
}


SENTINEL_LIVE_VALIDATION_PASS_VALUES = {"passed", "ok", "success"}


SENTINEL_DASHBOARD_UNSUPPORTED_QUERY_PATTERNS = (
    "Properties like",
)


def _as_sorted_strings(value):
    if isinstance(value, list):
        return sorted(str(item) for item in value if item)
    if value:
        return [str(value)]
    return []


def _sentinel_connector_names(connectors):
    names = []
    if not isinstance(connectors, list):
        return names
    for connector in connectors:
        if not isinstance(connector, dict):
            continue
        connector_id = connector.get("connector_id") or connector.get("connectorId")
        if connector_id:
            names.append(str(connector_id))
        for data_type in connector.get("data_types") or connector.get("dataTypes") or []:
            if data_type:
                names.append(str(data_type))
    return sorted(set(names))


def _sentinel_coverage_keys(payload):
    keys = []
    for table in _as_sorted_strings(payload.get("sentinel_tables")):
        keys.append(("table", table))
    if payload.get("level"):
        keys.append(("level", str(payload["level"])))
    mitre = payload.get("mitre_attack", {})
    if isinstance(mitre, dict):
        for technique in _as_sorted_strings(mitre.get("techniques")):
            keys.append(("technique", technique))
    for connector in _sentinel_connector_names(payload.get("required_data_connectors")):
        keys.append(("connector", connector))
    if not keys:
        keys.append(("query", payload.get("title", "")))
    return tuple(keys)


def _select_sentinel_dashboard_widgets(widgets, max_widgets):
    """Choose a deterministic, coverage-aware subset of Sentinel widgets."""
    remaining = sorted(widgets, key=lambda item: (item.get("title", ""), item.get("query_file", "")))
    selected = []
    covered = set()
    while remaining and len(selected) < max_widgets:
        best_index = 0
        best_score = None
        for index, widget in enumerate(remaining):
            coverage = set(widget.get("_coverage_keys", ()))
            new_coverage = len(coverage - covered)
            score = (-new_coverage, widget.get("title", ""), widget.get("query_file", ""))
            if best_score is None or score < best_score:
                best_index = index
                best_score = score
        widget = remaining.pop(best_index)
        covered.update(widget.get("_coverage_keys", ()))
        selected.append({key: value for key, value in widget.items() if not key.startswith("_")})
    return selected


def load_sentinel_dashboard_groups(queries_dir=QUERIES_DIR, max_widgets=24):
    """Load Sentinel dashboard groups from live-validated converted query JSON."""
    sentinel_dir = os.path.join(queries_dir, "sentinel")
    if not os.path.isdir(sentinel_dir):
        return {}

    grouped = {category: [] for category in SENTINEL_DASHBOARD_GROUPS}
    for filename in sorted(os.listdir(sentinel_dir)):
        if not filename.endswith(".json"):
            continue
        path = os.path.join(sentinel_dir, filename)
        try:
            with open(path) as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue

        if payload.get("source_type") != "microsoft_sentinel":
            continue
        if payload.get("conversion_status") != "promoted":
            continue
        if str(payload.get("live_validation_status", "")).lower() not in SENTINEL_LIVE_VALIDATION_PASS_VALUES:
            continue
        if any(pattern in payload.get("query", "") for pattern in SENTINEL_DASHBOARD_UNSUPPORTED_QUERY_PATTERNS):
            continue

        category = payload.get("sentinel_category", "")
        if category not in grouped:
            continue

        dashboard_meta = payload.get("dashboard", {})
        grouped[category].append({
            "title": f"Sentinel: {payload.get('title', filename)}",
            "query_file": f"sentinel/{filename}",
            "visualization_type": dashboard_meta.get("visualizationType", "table"),
            "_coverage_keys": _sentinel_coverage_keys(payload),
        })

    dashboards = {}
    for category, widgets in grouped.items():
        if not widgets:
            continue
        dashboards[SENTINEL_DASHBOARD_GROUPS[category]] = {
            "description": SENTINEL_DASHBOARD_DESCRIPTIONS[category],
            "widgets": _select_sentinel_dashboard_widgets(widgets, max_widgets),
        }
    return dashboards


DASHBOARDS.update(load_sentinel_dashboard_groups())


def select_dashboards(dashboard_names=None, dashboards=None):
    """Return a display-name keyed dashboard subset for targeted operations."""
    dashboards = dashboards or DASHBOARDS
    if not dashboard_names:
        return dashboards

    selected = {}
    name_lookup = {name.lower(): name for name in dashboards}
    missing = []
    for requested_name in dashboard_names:
        canonical_name = requested_name if requested_name in dashboards else None
        if canonical_name is None:
            canonical_name = name_lookup.get(requested_name.lower())
        if canonical_name is None:
            missing.append(requested_name)
            continue
        selected[canonical_name] = dashboards[canonical_name]

    if missing:
        available = ", ".join(sorted(dashboards))
        raise ValueError(
            f"unknown dashboard name(s): {', '.join(missing)}. "
            f"Available dashboards: {available}"
        )

    return selected
