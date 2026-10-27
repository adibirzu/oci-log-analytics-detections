"""Behavioral compatibility at catalog and setup-plan module boundaries."""
import hashlib
import io
import sys
from contextlib import redirect_stdout

import pytest


def test_catalog_public_facade_reexports_declared_definitions():
    from dashboards import catalog, definitions

    assert catalog.DASHBOARDS is definitions.DASHBOARDS
    assert catalog.octo_apm_workshop_widget("Example", "example.json") == {
        "title": "Example", "query_file": "example.json", "time_selection": {"timePeriod": "l21d"}
    }


def test_actual_inventory_output_bytes_match_pre_refactor_contract(tmp_path):
    from deploy_dashboard import build_dashboard_inventory, write_dashboard_inventory

    path = tmp_path / "inventory.json"
    inventory = build_dashboard_inventory(generated_at="2026-07-01T00:00:00+00:00")
    write_dashboard_inventory(path=str(path), inventory=inventory)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        "6570ef6e844b152fb765bc6396b47076a3a65594bdda74d965813e676e6e8858"
    )


@pytest.mark.parametrize("flag,digest", [
    (None, "a639a50db54a95dd70974f0cc6d4f4bf937c86f10e5f7d493324c08ff9a5fa8b"),
    ("--application-only", "62a80f0f7ae2a4511155fa426e81efe1c5f0fc81802539e04f9b5d8be4fb405a"),
    ("--octo-apm-only", "8754998cae84ca61ead2ea56e7ea63efe8a0d3cf3aaba0160fe0e6d13ad0248d"),
    ("--windows-access-only", "d83caac739e3b2164cd849825e7ca1a3aa48712f494461da7c1648010b1b3201"),
])
def test_pure_plan_and_cli_preserve_exact_output_without_provider_calls(monkeypatch, flag, digest):
    import setup_log_sources as setup
    from log_source_setup_plan import build_dry_run_plan

    def forbidden(*args, **kwargs):
        raise AssertionError("dry-run must not construct a provider client")

    monkeypatch.setattr(setup, "get_la_client", forbidden)
    monkeypatch.setattr(sys, "argv", ["setup_log_sources.py", "--dry-run", *([flag] if flag else [])])
    output = io.StringIO()
    with redirect_stdout(output):
        setup.main()
    plan = build_dry_run_plan(
        application_only=flag == "--application-only",
        octo_apm_only=flag == "--octo-apm-only",
        windows_access_only=flag == "--windows-access-only",
    )
    assert output.getvalue() == plan
    assert hashlib.sha256(plan.encode()).hexdigest() == digest


def test_application_setup_retains_guarded_provider_call_sequence(monkeypatch):
    import setup_log_sources as setup

    calls = []
    client = object()

    def record(name, result):
        def call(*args, **kwargs):
            calls.append((name, args, kwargs))
            return result
        return call

    bindings = {
        "get_la_client": client, "get_namespace": "SYNTHETIC",
        "resolve_compartment_id": "synthetic-compartment", "assert_write_allowed": None,
        "list_available_log_sources": set(), "create_fields": {},
        "build_existing_field_map": {}, "create_parser": None, "create_source": None,
    }
    for name, result in bindings.items():
        monkeypatch.setattr(setup, name, record(name, result))
    monkeypatch.setattr(sys, "argv", ["setup_log_sources.py", "--application-only"])
    with redirect_stdout(io.StringIO()):
        setup.main()
    assert [name for name, _, _ in calls] == list(bindings)
    assert calls[0][2] == {"timeout": (10, setup.LOG_ANALYTICS_READ_TIMEOUT_SECONDS)}
    assert calls[3][1:] == (("synthetic-compartment",), {"override": False})
    assert calls[-2][1][:3] == (client, "SYNTHETIC", setup.APP_PARSER_NAME)
    assert calls[-1][1] == (
        client, "SYNTHETIC", "synthetic-compartment", setup.APP_SOURCE_INTERNAL,
        setup.APP_SOURCE_DISPLAY, setup.APP_SOURCE_DESC, setup.APP_PARSER_NAME,
    )
