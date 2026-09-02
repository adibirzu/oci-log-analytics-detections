"""Structural and safety contracts for the Log Analytics/Splunk diagrams."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIAGRAMS = ROOT / "docs" / "diagrams"
BASENAMES = (
    "logan-splunk-architecture",
    "logan-splunk-raw-fanout",
    "logan-splunk-evidence-export",
    "logan-splunk-onprem-agent",
    "logan-splunk-export-sequence",
    "logan-splunk-replay-state",
    "logan-splunk-iam-boundaries",
    "logan-splunk-onboarding",
    "logan-splunk-validation",
    "logan-splunk-troubleshooting",
)
REQUIRED_COMPONENTS = (
    "oci-splunk",
    "Management Agent",
    "Log Analytics",
    "Monitoring",
    "Notifications",
    "Function",
    "Vault",
    "checkpoint/DLQ",
    "Splunk HEC",
)
UNSAFE_MERMAID = re.compile(
    r"(?im)^\s*click\s+|<script|javascript:|%%\{\s*init"
)
TENANT_SPECIFIC = re.compile(
    r"(?i)ocid1\.|https?://|www\.|(?:\d{1,3}\.){3}\d{1,3}|"
    r"(?:password|api[_ -]?key|authorization)\s*[:=]"
)
FLOWCHART_NODE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9_]*)\["([^"]+)"\]\s*$')
FLOWCHART_EDGE = re.compile(
    r'^\s*([A-Za-z][A-Za-z0-9_]*)\s+(?:-->|-\.->|==>)\|"([^"]+)"\|\s*'
    r'([A-Za-z][A-Za-z0-9_]*)\s*$'
)
FOCUSED_TOPOLOGY = {
    "logan-splunk-iam-boundaries": {
        "groups": {
            "connector": "Connector Hub service principal",
            "streaming": "Independent raw transport",
            "oci_splunk": "Independent raw transport",
            "notifications": "Notifications service principal",
            "function": "Function dynamic group principal",
            "logan": "Function permission targets",
            "vault": "Function permission targets",
            "state": "Function permission targets",
            "hec": "Customer-managed destination",
        },
        "edges": {
            ("connector", "streaming"): "control: scoped stream-push permission",
            ("streaming", "oci_splunk"): "telemetry: raw records",
            ("oci_splunk", "hec"): "telemetry: raw HEC batches",
            ("hec", "oci_splunk"): "response: raw delivery receipt",
            ("notifications", "function"): "control: invoke exact Function",
            ("function", "logan"): "control: Log Analytics query permission",
            ("function", "vault"): "control: one secret-bundle read",
            ("function", "state"): "control: checkpoint and DLQ object access",
            ("function", "hec"): "telemetry: evidence batch",
            ("hec", "function"): "response: HEC acceptance",
        },
    },
    "logan-splunk-onboarding": {
        "groups": {
            "owner": "Ownership and mode",
            "mode": "Ownership and mode",
            "raw_route": "Raw branch",
            "oci_splunk": "Raw branch",
            "logan": "Evidence branch",
            "evidence_export": "Evidence branch",
            "hec": "Shared destination",
            "join": "Acceptance",
            "acceptance": "Acceptance",
        },
        "edges": {
            ("owner", "mode"): "control: approve source, retention, and mode",
            ("mode", "raw_route"): "control: raw selected",
            ("raw_route", "oci_splunk"): "telemetry: Connector Hub to Streaming records",
            ("oci_splunk", "hec"): "telemetry: raw HEC batches",
            ("mode", "logan"): "control: evidence selected",
            ("logan", "evidence_export"): "telemetry: detection evidence",
            ("evidence_export", "hec"): "telemetry: normalized evidence batches",
            ("hec", "join"): "response: selected-mode search receipts",
            ("mode", "join"): "control: both requires two independent receipts",
            ("join", "acceptance"): "control: record selected-mode acceptance",
        },
    },
    "logan-splunk-onprem-agent": {
        "groups": {
            "host": "On-premises source",
            "agent": "On-premises source",
            "gateway": "On-premises source",
            "association": "OCI analytics",
            "logan": "OCI analytics",
            "detection": "OCI analytics",
            "function": "OCI analytics",
            "hec": "Customer-managed destination",
            "response": "Customer-managed destination",
        },
        "edges": {
            ("host", "agent"): "telemetry: collected records",
            ("agent", "association"): "telemetry: direct Log Analytics ingestion",
            ("agent", "gateway"): "telemetry: optional gateway path",
            ("gateway", "association"): "telemetry: relayed Log Analytics ingestion",
            ("association", "logan"): "telemetry: parsed associated records",
            ("logan", "detection"): "telemetry: detection evidence",
            ("detection", "function"): "control: reviewed trigger chain",
            ("function", "hec"): "telemetry: normalized evidence only",
            ("hec", "response"): "response: searchable evidence",
        },
    },
    "logan-splunk-validation": {
        "groups": {
            "source": "Selected-mode scope",
            "connector": "Raw-route gates",
            "streaming": "Raw-route gates",
            "oci_splunk": "Raw-route gates",
            "logan": "Evidence-route gates",
            "evidence_gate": "Evidence-route gates",
            "hec": "Shared destination gates",
            "search": "Shared destination gates",
            "release": "Release boundary",
        },
        "edges": {
            ("source", "connector"): "telemetry: raw canary",
            ("connector", "streaming"): "telemetry: Connector Hub delivery",
            ("streaming", "oci_splunk"): "telemetry: stream consumption",
            ("oci_splunk", "hec"): "telemetry: raw HEC batch",
            ("source", "logan"): "telemetry: evidence canary",
            ("logan", "evidence_gate"): "telemetry: parse, detection, metric, and invocation",
            ("evidence_gate", "hec"): "telemetry: evidence HEC batch",
            ("hec", "search"): "response: accepted and searchable",
            ("search", "release"): "control: accept every selected mode",
        },
    },
    "logan-splunk-troubleshooting": {
        "groups": {
            "symptom": "Symptom",
            "connector": "Raw route",
            "streaming": "Raw route",
            "oci_splunk": "Raw route",
            "logan": "Evidence route",
            "trigger": "Evidence route",
            "function_state": "Evidence route",
            "hec": "Shared destination",
            "search": "Shared destination",
        },
        "edges": {
            ("symptom", "connector"): "control: inspect raw route upstream",
            ("connector", "streaming"): "telemetry: verify Connector Hub delivery",
            ("streaming", "oci_splunk"): "telemetry: inspect lag and consumption",
            ("oci_splunk", "hec"): "telemetry: retry-safe raw batch",
            ("symptom", "logan"): "control: verify bounded evidence query",
            ("logan", "trigger"): "telemetry: inspect metric and notification",
            ("trigger", "function_state"): "control: inspect invocation, checkpoint, and DLQ",
            ("function_state", "hec"): "telemetry: retry-safe evidence batch",
            ("hec", "search"): "response: accepted and searchable",
        },
    },
}


def _pair(name: str) -> tuple[Path, Path]:
    return DIAGRAMS / f"{name}.mmd", DIAGRAMS / f"{name}.excalidraw"


def _scene(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _mermaid_topology(path: Path) -> tuple[dict[str, str], dict[tuple[str, str], str]]:
    groups: dict[str, str] = {}
    edges: dict[tuple[str, str], str] = {}
    current_group: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        group_match = re.fullmatch(r'subgraph\s+\w+\["([^"]+)"\]', line)
        if group_match:
            current_group = group_match.group(1)
            continue
        if line == "end":
            current_group = None
            continue
        node_match = FLOWCHART_NODE.fullmatch(line)
        if node_match and current_group is not None:
            groups[node_match.group(1)] = current_group
            continue
        edge_match = FLOWCHART_EDGE.fullmatch(line)
        if edge_match:
            edges[(edge_match.group(1), edge_match.group(3))] = edge_match.group(2)
    return groups, edges


def _excalidraw_topology(
    path: Path,
) -> tuple[dict[str, str], dict[tuple[str, str], str]]:
    elements = _scene(path)["elements"]
    assert isinstance(elements, list)
    groups = {
        element["id"]: element["customData"]["group"]
        for element in elements
        if isinstance(element, dict)
        and element.get("type") == "rectangle"
        and isinstance(element.get("customData"), dict)
        and element["customData"].get("primaryObject") is True
    }
    edges = {
        (element["customData"]["from"], element["customData"]["to"]):
        element["customData"]["label"]
        for element in elements
        if isinstance(element, dict)
        and element.get("type") == "arrow"
        and isinstance(element.get("customData"), dict)
        and "from" in element["customData"]
        and "to" in element["customData"]
    }
    return groups, edges


def _assert_excalidraw_boundary_geometry(
    path: Path, expected_groups: dict[str, str]
) -> None:
    elements = _scene(path)["elements"]
    assert isinstance(elements, list)
    boundaries = {
        element["customData"]["label"]: element
        for element in elements
        if isinstance(element, dict)
        and element.get("type") == "rectangle"
        and isinstance(element.get("customData"), dict)
        and element["customData"].get("boundary") is True
    }
    primary = {
        element["id"]: element
        for element in elements
        if isinstance(element, dict)
        and element.get("type") == "rectangle"
        and isinstance(element.get("customData"), dict)
        and element["customData"].get("primaryObject") is True
    }
    assert set(boundaries) == set(expected_groups.values()), path
    for node_id, group in expected_groups.items():
        node = primary[node_id]
        boundary = boundaries[group]
        assert boundary["x"] <= node["x"], (path, node_id, "left")
        assert boundary["y"] <= node["y"], (path, node_id, "top")
        assert boundary["x"] + boundary["width"] >= node["x"] + node["width"], (
            path,
            node_id,
            "right",
        )
        assert boundary["y"] + boundary["height"] >= node["y"] + node["height"], (
            path,
            node_id,
            "bottom",
        )


def test_inventory_has_ten_editable_pairs_and_main_spec() -> None:
    assert (DIAGRAMS / "logan-splunk-architecture.json").is_file()
    assert len(BASENAMES) == 10
    for name in BASENAMES:
        mermaid, excalidraw = _pair(name)
        assert mermaid.is_file(), mermaid
        assert excalidraw.is_file(), excalidraw


def test_mermaid_sources_have_required_header_scope_and_safe_syntax() -> None:
    for name in BASENAMES:
        mermaid, _ = _pair(name)
        text = mermaid.read_text(encoding="utf-8")
        lines = text.splitlines()
        assert lines[0].startswith("%% Title:"), mermaid
        assert lines[1].startswith("%% Evidence:"), mermaid
        assert "provider verified" in lines[1], mermaid
        assert "release accepted" in lines[1], mermaid
        match = re.search(r"(?m)^%% Primary objects: ([0-9]+)$", text)
        assert match, mermaid
        assert 5 <= int(match.group(1)) <= 9, mermaid
        assert re.search(
            r"(?m)^(?:flowchart|sequenceDiagram|stateDiagram-v2)\b", text
        ), mermaid
        assert not UNSAFE_MERMAID.search(text), mermaid


def test_excalidraw_sources_are_local_editable_and_bounded() -> None:
    for name in BASENAMES:
        _, excalidraw = _pair(name)
        scene = _scene(excalidraw)
        assert scene.get("type") == "excalidraw", excalidraw
        assert scene.get("version") == 2, excalidraw
        assert scene.get("files") == {}, excalidraw
        elements = scene.get("elements")
        assert isinstance(elements, list), excalidraw
        assert 5 <= sum(
            element.get("type") == "rectangle"
            and isinstance(element.get("customData"), dict)
            and element["customData"].get("primaryObject") is True
            for element in elements
            if isinstance(element, dict)
        ) <= 9, excalidraw
        assert not any(
            element.get("type") in {"embeddable", "iframe", "image"}
            or element.get("link") is not None
            for element in elements
            if isinstance(element, dict)
        ), excalidraw


def test_inventory_uses_implemented_component_names_and_flow_types() -> None:
    corpus = "\n".join(
        path.read_text(encoding="utf-8")
        for name in BASENAMES
        for path in _pair(name)
    )
    for component in REQUIRED_COMPONENTS:
        assert component in corpus
    for flow_type in ("telemetry", "control", "response"):
        assert flow_type in corpus


def test_paired_views_share_primary_object_terminology() -> None:
    for name in BASENAMES:
        mermaid, excalidraw = _pair(name)
        mermaid_text = mermaid.read_text(encoding="utf-8")
        elements = _scene(excalidraw)["elements"]
        assert isinstance(elements, list)
        primary_ids = {
            element["id"]
            for element in elements
            if isinstance(element, dict)
            and element.get("type") == "rectangle"
            and isinstance(element.get("customData"), dict)
            and element["customData"].get("primaryObject") is True
        }
        labels = {
            element["id"].removeprefix("__oci_label_"): element["text"]
            for element in elements
            if isinstance(element, dict)
            and element.get("type") == "text"
            and str(element.get("id", "")).startswith("__oci_label_")
        }
        assert primary_ids == labels.keys(), excalidraw
        for label in labels.values():
            assert label in mermaid_text, (name, label)


def test_critical_views_match_explicit_boundary_and_edge_contracts() -> None:
    for name, contract in FOCUSED_TOPOLOGY.items():
        mermaid, excalidraw = _pair(name)
        mermaid_groups, mermaid_edges = _mermaid_topology(mermaid)
        excalidraw_groups, excalidraw_edges = _excalidraw_topology(excalidraw)
        assert mermaid_groups == contract["groups"], (name, "Mermaid boundaries")
        assert excalidraw_groups == contract["groups"], (name, "Excalidraw boundaries")
        assert mermaid_edges == contract["edges"], (name, "Mermaid edges")
        assert excalidraw_edges == contract["edges"], (name, "Excalidraw edges")
        _assert_excalidraw_boundary_geometry(excalidraw, contract["groups"])


def test_main_spec_matches_implemented_architecture_inventory() -> None:
    spec = json.loads(
        (DIAGRAMS / "logan-splunk-architecture.json").read_text(encoding="utf-8")
    )
    assert spec["evidence"] == {
        "code_backed": True,
        "provider_verified": False,
        "release_accepted": False,
    }
    assert 5 <= len(spec["nodes"]) <= 9
    assert {node["label"] for node in spec["nodes"]} == set(REQUIRED_COMPONENTS)
    assert {edge["type"] for edge in spec["edges"]} >= {
        "telemetry",
        "control",
        "response",
    }
    mermaid = (DIAGRAMS / "logan-splunk-architecture.mmd").read_text(
        encoding="utf-8"
    )
    scene = _scene(DIAGRAMS / "logan-splunk-architecture.excalidraw")
    elements = scene["elements"]
    assert isinstance(elements, list)
    primary_ids = {
        element["id"]
        for element in elements
        if isinstance(element, dict)
        and element.get("type") == "rectangle"
        and isinstance(element.get("customData"), dict)
        and element["customData"].get("primaryObject") is True
    }
    generated_edge_labels = {
        element["customData"]["label"]
        for element in elements
        if isinstance(element, dict)
        and element.get("type") == "arrow"
        and isinstance(element.get("customData"), dict)
    }
    assert primary_ids == {node["id"] for node in spec["nodes"]}
    assert generated_edge_labels == {edge["label"] for edge in spec["edges"]}
    for node in spec["nodes"]:
        assert f"= {node['id']} (oci-service:" in mermaid
        assert node["label"] in mermaid


def test_all_sources_are_tenant_neutral_and_contain_no_sensitive_values() -> None:
    paths = [DIAGRAMS / "logan-splunk-architecture.json"] + [
        path for name in BASENAMES for path in _pair(name)
    ]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert not TENANT_SPECIFIC.search(text), path
