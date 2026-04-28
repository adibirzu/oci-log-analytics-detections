"""Canonical OCI Audit Event schema builder.

Aligns with the real OCI Audit API v2.0 response shape (CloudEvents v0.1
envelope), verified against `oci audit event list` output on 2026-04-24.

Top-level envelope fields (camelCase, as emitted by OCI Streaming / Log
Analytics ingest):
    cloudEventsVersion, contentType, eventId, eventTime, eventType,
    eventTypeVersion, source

Nested `data` fields:
    additionalDetails, availabilityDomain, compartmentId, compartmentName,
    definedTags, eventGroupingId, eventName, freeformTags,
    identity{authType, callerId, callerName, consoleSessionId, credentials,
             ipAddress, principalId, principalName, tenantId, userAgent},
    request{action, headers, id, parameters, path},
    resourceId, resourceName,
    response{headers, message, payload, responseTime, status},
    stateChange{current, previous}

OCI Log Analytics parsed display-name columns (added at ingest):
    'Event ID', 'Event Type', 'Event Name', 'User Name', 'Source IP',
    'Compartment Name', 'Compartment OCID', 'Response Code', 'Log Source'

The multicloud wrapper preserves `cloudProvider` and `log_source_identifier`
tags for cross-cloud correlation; these are NOT part of raw OCI audit.
"""

from __future__ import annotations

import uuid
from typing import Any


def build_oci_audit_event(
    event_type: str,
    *,
    event_time: str,
    principal_id: str,
    principal_name: str,
    auth_type: str,
    ip_address: str,
    compartment_id: str,
    compartment_name: str,
    tenant_id: str,
    availability_domain: str = "AD-1",
    resource_name: str = "",
    resource_id: str | None = None,
    request_action: str = "POST",
    request_path: str | None = None,
    request_parameters: dict[str, Any] | None = None,
    user_agent: str = "Oracle-JavaSDK/2.0",
    response_status: str = "200",
    response_message: str = "",
    response_payload: dict[str, Any] | None = None,
    state_previous: dict[str, Any] | None = None,
    state_current: dict[str, Any] | None = None,
    additional_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a single OCI audit event matching the real CloudEvents v0.1 schema.

    All fields use camelCase keys (matching OCI Log Analytics ingest format).
    OCL display-name parallel fields are added at the top level so OCL queries
    against normalized columns ('Event Type', 'Source IP', etc.) match.
    """
    event_name = event_type.split(".")[-1] if "." in event_type else event_type
    source = event_type.split(".")[2] if event_type.count(".") >= 2 else "audit"

    if request_path is None:
        request_path = f"/20160918/{event_name.lower()}s"
    if response_message == "":
        response_message = f"{event_name} succeeded" if response_status.startswith("2") else f"{event_name} failed"

    data: dict[str, Any] = {
        "additionalDetails": additional_details,
        "availabilityDomain": availability_domain,
        "compartmentId": compartment_id,
        "compartmentName": compartment_name,
        "definedTags": None,
        "eventGroupingId": f"csid{uuid.uuid4().hex[:16]}/{uuid.uuid4().hex[:16]}/{uuid.uuid4().hex[:16].upper()}",
        "eventName": event_name,
        "freeformTags": None,
        "identity": {
            "authType": auth_type,
            "callerId": None,
            "callerName": None,
            "consoleSessionId": f"csid{uuid.uuid4().hex[:16]}" if auth_type == "natv" else None,
            "credentials": f"ocid1.credential.oc1..{uuid.uuid4().hex[:12]}",
            "ipAddress": ip_address,
            "principalId": principal_id,
            "principalName": principal_name,
            "tenantId": tenant_id,
            "userAgent": user_agent,
        },
        "request": {
            "action": request_action,
            "headers": {
                "Accept": ["*/*"],
                "User-Agent": [user_agent],
                "opc-request-id": [f"{uuid.uuid4().hex[:12].upper()}"],
            },
            "id": str(uuid.uuid4()),
            "parameters": request_parameters or {},
            "path": request_path,
        },
        "resourceId": resource_id,
        "resourceName": resource_name,
        "response": {
            "headers": {
                "Content-Type": ["application/json"],
                "opc-request-id": [f"{uuid.uuid4().hex[:12].upper()}"],
            },
            "message": response_message,
            "payload": response_payload or {},
            "responseTime": event_time,
            "status": response_status,
        },
        "stateChange": {
            "current": state_current,
            "previous": state_previous,
        },
    }

    event_id = str(uuid.uuid4())
    return {
        # Multicloud wrapper tags (not part of raw OCI audit; preserved for
        # cross-cloud correlation in OCL queries)
        "cloudProvider": "OCI",
        "log_source_identifier": "OCI Audit Logs",
        # CloudEvents v0.1 envelope (real OCI audit top-level fields)
        "cloudEventsVersion": "0.1",
        "contentType": "application/json",
        "eventId": event_id,
        "eventTime": event_time,
        "eventType": event_type,
        "eventTypeVersion": "2.0",
        "source": source,
        "data": data,
        # OCL display-name parallel columns (populated by OCI Log Analytics
        # parser at ingest; included here so detection_logs match OCL queries
        # that reference 'Event Type', 'Source IP', etc.)
        "Log Source": "OCI Audit Logs",
        "Event ID": event_id,
        "Event Type": event_type,
        "Event Name": event_name,
        "User Name": principal_name,
        "Source IP": ip_address,
        "Client IP": ip_address,
        "Compartment Name": compartment_name,
        "Compartment OCID": compartment_id,
        "Principal Name": principal_name,
        "Principal ID": principal_id,
        "Tenant ID": tenant_id,
        "Response Code": response_status,
        "Type": event_type,
    }
