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


def _pair(name: str) -> tuple[Path, Path]:
    return DIAGRAMS / f"{name}.mmd", DIAGRAMS / f"{name}.excalidraw"


def _scene(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


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
