"""Windows Sysmon synthetic events compatibility facade."""

from testlogs.windows_sysmon_core import sysmon_event
from testlogs.windows_sysmon_bluelight import _bluelight_kill_chain_sysmon_events
from testlogs.windows_sysmon_events import generate_windows_events

__all__ = ["sysmon_event", "_bluelight_kill_chain_sysmon_events", "generate_windows_events"]
