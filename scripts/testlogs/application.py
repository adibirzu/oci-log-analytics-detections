"""Application synthetic events compatibility facade."""

from testlogs.application_core import application_event
from testlogs.application_events import generate_application_events
from testlogs.application_oke import generate_oke_kubernetes_attack_events

__all__ = ["application_event", "generate_application_events", "generate_oke_kubernetes_attack_events"]
