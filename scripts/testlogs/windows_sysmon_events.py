"""Windows Sysmon synthetic event batch facade."""

from testlogs.windows_sysmon_base_events import _base_windows_events
from testlogs.windows_sysmon_advanced_events import _advanced_windows_events
from testlogs.windows_sysmon_recent_events import _hunting_and_recent_windows_events


def generate_windows_events():
    """Generate Windows Sysmon events covering all Windows rules."""
    events = []
    events.extend(_base_windows_events())
    events.extend(_advanced_windows_events())
    events.extend(_hunting_and_recent_windows_events())
    return events
