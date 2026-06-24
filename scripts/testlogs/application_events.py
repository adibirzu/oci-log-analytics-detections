"""Application and browser synthetic event batch facade."""

from testlogs.application_apm import _apm_demo_application_events
from testlogs.application_baseline import _baseline_application_events
from testlogs.application_oke import generate_oke_kubernetes_attack_events


def generate_application_events():
    """Generate application and browser telemetry for App 360 and browser dashboards."""
    events = []
    events.extend(_baseline_application_events())
    events.extend(_apm_demo_application_events())
    events.extend(generate_oke_kubernetes_attack_events())
    return events
