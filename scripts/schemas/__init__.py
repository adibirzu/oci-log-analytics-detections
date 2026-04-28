"""Canonical CSP-native log schema builders.

Ported from /Users/abirzu/dev/multicloudoperations/shared/* on 2026-04-28.
These builders produce records matching the real cloud-provider log shapes:

- ``oci_audit_schema`` — OCI Audit (CloudEvents v0.1, eventTypeVersion 2.0)
- ``windows_audit_schema`` — Windows Security + Sysmon native EVTX field names
- ``azure_audit_schema`` — Azure Monitor diagnostic-settings export shape
- ``gcp_audit_schema`` — Google Cloud LogEntry + AuditLog protobuf shape

Each builder emits dual-keyed records: native CSP envelope at top level (real
field names a tenant ingest pipeline would receive) plus parallel OCI Log
Analytics display-name columns (``Event ID``, ``Source IP``, ``Compartment
Name``, etc.) that detection queries use directly.

The ``log_source_identifier`` and ``cloudProvider`` keys are multicloud
wrappers preserved for cross-cloud correlation; they are not part of the raw
CSP envelopes.
"""

from .azure_audit_schema import (
    build_azure_activity_event,
    build_azure_audit_event,
    build_azure_signin_event,
)
from .gcp_audit_schema import build_gcp_audit_event
from .oci_audit_schema import build_oci_audit_event
from .windows_audit_schema import (
    build_windows_security_event,
    build_windows_sysmon_event,
)

__all__ = [
    "build_oci_audit_event",
    "build_windows_security_event",
    "build_windows_sysmon_event",
    "build_azure_activity_event",
    "build_azure_audit_event",
    "build_azure_signin_event",
    "build_gcp_audit_event",
]
