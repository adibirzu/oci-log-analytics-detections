import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_cross_siem_catalog_generation_and_query_mappings():
    subprocess.run([sys.executable, "scripts/generate_cross_siem_detection_catalog.py"], cwd=ROOT, check=True)
    catalog = json.loads((ROOT / "queries/cross_siem_detection_catalog.json").read_text())
    assert {p["id"] for p in catalog["products"]} == {"splunk", "microsoft_sentinel", "qradar", "logrhythm", "arcsight", "elastic"}
    assert all(family["logan_queries"] for family in catalog["detection_families"])

def test_catalog_does_not_embed_third_party_rule_bodies():
    serialized = (ROOT / "config/cross_siem_detection_catalog.json").read_text().lower()
    assert "rule_body" not in serialized
    assert "query_body" not in serialized

def test_existing_synthetic_oci_audit_covers_new_cloud_hunts():
    sys.path.insert(0, str(ROOT / "scripts"))
    from testlogs.oci_audit import generate_oci_audit_events

    events = generate_oci_audit_events()
    by_actor = {}
    for event in events:
        actor = (event.get("User Name"), event.get("Source IP"))
        by_actor.setdefault(actor, set()).add(event.get("Event Type"))

    assert any(len({e for e in actions if e and ".list" in e}) >= 5 for actions in by_actor.values())
    assert any(
        "com.oraclecloud.objectstorage.getobject" in actions
        and "com.oraclecloud.objectstorage.createpreauthenticatedrequest" in actions
        for actions in by_actor.values()
    )
    assert any(
        "com.oraclecloud.consolesignon.login" in actions
        and "com.oraclecloud.identitycontrolplane.createauthtoken" in actions
        and "com.oraclecloud.objectstorage.getobject" in actions
        for actions in by_actor.values()
    )
