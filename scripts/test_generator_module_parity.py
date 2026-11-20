"""Behavioral byte parity for fixed synthetic generator inputs and public facades."""

import hashlib
import importlib
import json

import pytest

import generate_logan_workbench_artifacts as workbench
import generate_synthetic_2026_campaign as campaign

# Synthetic baselines were regenerated on sanitized pre-refactor commit 788e6bc.
EXPECTED = {
    "patterns.json": "4e9d3de0ff6a6b224926e43718851085ad1af4953d2547e4ca471e6c02722695",
    "examples.json": "021c9374522392c002a1a0b5e59ab016ed4841daadbb136ea874f3cff0c72b04",
    "reference.json": "a91be814f36d8579537ac5fe288845588b57658814cf1ad79726d980ac7ed301",
    "story-default-off.json": "8876650d1be9c74382cd6e13c51fdd05fbccdd303d53fa3299092986f27f32a4",
    "campaign-default-off.json": "680e68b27bf91afbf9b03e200e71ff57d6381174bf428a66d33290130c998aab",
    "story-default-partial.json": "8876650d1be9c74382cd6e13c51fdd05fbccdd303d53fa3299092986f27f32a4",
    "campaign-default-partial.json": "e4d734e4f501731d97b388f7166e66192bc319b6e400a3afe8c5c9cd756ca6f8",
    "story-default-strict.json": "8876650d1be9c74382cd6e13c51fdd05fbccdd303d53fa3299092986f27f32a4",
    "campaign-default-strict.json": "c1a1c5fdc07e000fbc235a5e2e18a7f1f2fd1676945fe404a6f7d5ea30f599b8",
    "story-custom-off.json": "c54b0e0195b24f07944c625214f3048eb14a6db70bbbd9d0be9d4afe89532377",
    "campaign-custom-off.json": "0f91d2aa9135ce475f9cd4f70945b0e2ab9343173ad4b830713eea490ccbdce7",
    "story-custom-partial.json": "c54b0e0195b24f07944c625214f3048eb14a6db70bbbd9d0be9d4afe89532377",
    "campaign-custom-partial.json": "8150c12750b3fc46e7c5ce351df1672d56046adc53e12a675fa427b1c3bda7b9",
    "story-custom-strict.json": "c54b0e0195b24f07944c625214f3048eb14a6db70bbbd9d0be9d4afe89532377",
    "campaign-custom-strict.json": "340d2875a7c444a8e84bf888d5801cc193da3b31ac1a915650ecea370678bc22",
    "cli-stdout.json": "09d228b698d7a851a05a98f365e6319ecbece7fcfa2b1adc7b523de7a7b7ef7b",
}


def digest(payload):
    return hashlib.sha256(
        (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    ).hexdigest()


@pytest.mark.parametrize("name", ["patterns", "examples", "reference"])
def test_workbench_original_generated_bytes(monkeypatch, name):
    monkeypatch.setattr(workbench, "now_iso", lambda: "2026-01-02T03:04:05Z")
    value = (
        workbench.build_reference_catalog(False)
        if name == "reference"
        else getattr(workbench, "build_" + name)()
    )
    assert digest(value) == EXPECTED[name + ".json"]


@pytest.mark.parametrize(
    "label,seed,when,env",
    [
        ("default", "fixture-a", "2026-10-20T21:00:00Z", {}),
        (
            "custom",
            "fixture-b",
            "2027-01-02T05:06:07+02:00",
            {
                "OCI_DEMO_PREFIX": "fixture",
                "DNS_DOMAIN": "fixture.example",
                "GUARDIAN_ADB_NAME": "guardian-fixture",
                "OBSERVEAI_ADB_NAME": "observe-fixture",
                "OCI_REGION": "us-fixture-1",
            },
        ),
    ],
)
@pytest.mark.parametrize("mask", ["off", "partial", "strict"])
@pytest.mark.parametrize("kind", ["story", "campaign"])
def test_synthetic_original_bytes_and_event_order(label, seed, when, env, mask, kind):
    if kind == "story":
        value = campaign.generate_7day_storyline_bundle(
            seed=seed, reference_time=when, env=env, mask_mode=mask
        )
    else:
        value = campaign.generate_campaign_bundle(
            seed=seed, base_time=when, env=env, mask_mode=mask
        )
    assert digest(value) == EXPECTED[f"{kind}-{label}-{mask}.json"]
    story = value if kind == "story" else value["storyline_7day"]
    assert (
        story["all_logs"]
        == story["background_logs"]
        + story["attack_logs"]
        + story["multicloud_logs"]
        + story["ac_hunter_telemetry"]
    )


@pytest.mark.parametrize("kind", ["patterns", "examples"])
def test_extracted_workbench_builders_take_time_as_explicit_input(kind):
    module = importlib.import_module("logan_workbench_" + kind)
    builder = getattr(module, "build_" + kind)
    value = builder(generated_at="2026-01-02T03:04:05Z")
    assert digest(value) == EXPECTED[kind + ".json"]
    assert (
        builder(generated_at="2030-01-01T00:00:00Z")["generated_at"]
        == "2030-01-01T00:00:00Z"
    )


def test_public_package_import_without_scripts_pythonpath():
    import os
    from pathlib import Path
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from scripts.generate_synthetic_2026_campaign import generate_7day_storyline_bundle; assert generate_7day_storyline_bundle(env={}, reference_time='2026-10-20T21:00:00Z')['storyline_counts']['distinct_dates'] == 7",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "PYTHONPATH": "."},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_campaign_script_cli_preserves_summary_bytes():
    import subprocess
    import sys
    from pathlib import Path

    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("generate_synthetic_2026_campaign.py")),
            "--seed",
            "fixture-cli",
            "--mask",
            "off",
            "--dry-run",
        ],
        capture_output=True,
        check=True,
    )
    assert hashlib.sha256(result.stdout).hexdigest() == EXPECTED["cli-stdout.json"]


def test_network_metric_uses_explicit_fixture_indicator():
    from synthetic_campaign_metrics import build_multicloud_metrics

    metrics = build_multicloud_metrics(
        rmm_relay_ip="203.0.113.55",
        aws_region="aws-fixture",
        azure_region="azure-fixture",
        gcp_region="gcp-fixture",
        oci_region="oci-fixture",
        d4_ts2="2026-01-01T00:00:00Z",
        d5_ts3="2026-01-01T00:00:00Z",
        d6_ts1="2026-01-01T00:00:00Z",
        d7_ts1="2026-01-01T00:00:00Z",
        d7_ts2="2026-01-01T00:00:00Z",
        d7_ts3="2026-01-01T00:00:00Z",
        day_traces={day: f"trace-{day}" for day in range(1, 8)},
    )
    assert metrics[1]["dimensions"] == {
        "cloud_provider": "Azure",
        "region": "azure-fixture",
        "c2_ip": "203.0.113.55",
        "trace_id": "trace-4",
    }
