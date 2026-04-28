"""Canonical GCP Cloud Audit Log schema builder.

Aligns with the real Google Cloud Audit Log format (LogEntry + AuditLog proto),
verified against `gcloud logging read logName:cloudaudit.googleapis.com` on
2026-04-24. The shape is the same whether logs are read via:
    - Cloud Logging API (LogEntry JSON)
    - Pub/Sub sink export (newline-delimited LogEntry JSON)
    - BigQuery sink
    - OCI Log Analytics (after ingest through Pub/Sub -> OCI Streaming)

Top-level LogEntry fields:
    insertId, logName, resource{type, labels}, severity, timestamp,
    receiveTimestamp, labels, operation, protoPayload

protoPayload is a google.cloud.audit.AuditLog wrapped:
    @type: "type.googleapis.com/google.cloud.audit.AuditLog"
    methodName: "google.iam.admin.v1.SetIamPolicy"
    serviceName: "iam.googleapis.com"
    resourceName: "projects/PROJECT/serviceAccounts/SA"
    authenticationInfo{principalEmail, principalSubject, authoritySelector}
    requestMetadata{callerIp, callerSuppliedUserAgent, requestAttributes}
    authorizationInfo[{granted, permission, resource, resourceAttributes}]
    request{...}
    response{...}
    status{code, message}

OCI Log Analytics parsed display-name columns added at ingest:
    'Log Source', 'Event Name', 'User Name', 'Source IP', 'Client IP',
    'Project ID', 'Method Name', 'Service Name', 'Severity'
"""

from __future__ import annotations

import uuid
from typing import Any


def build_gcp_audit_event(
    *,
    event_time: str,
    project_id: str,
    method_name: str,
    service_name: str,
    principal_email: str,
    caller_ip: str,
    resource_type: str = "project",
    resource_name: str = "",
    resource_labels: dict[str, str] | None = None,
    severity: str = "INFO",
    status_code: int = 0,
    status_message: str = "",
    user_agent: str = "google-cloud-sdk",
    authorization_permission: str = "",
    authorization_granted: bool = True,
    request_payload: dict[str, Any] | None = None,
    response_payload: dict[str, Any] | None = None,
    log_type: str = "activity",
) -> dict[str, Any]:
    """Build a single GCP Cloud Audit Log entry matching the real LogEntry+AuditLog shape.

    log_type in {"activity", "data_access", "system_event", "policy"}
    determines the logName path segment.
    """
    insert_id = f"{uuid.uuid4().hex[:20]}"
    event_short = method_name.split(".")[-1] if "." in method_name else method_name

    if resource_name == "":
        resource_name = f"projects/{project_id}"
    resource_labels = resource_labels or {"project_id": project_id}

    proto_payload: dict[str, Any] = {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "status": {"code": status_code, "message": status_message},
        "authenticationInfo": {
            "principalEmail": principal_email,
            "principalSubject": f"user:{principal_email}",
            "authoritySelector": "",
        },
        "requestMetadata": {
            "callerIp": caller_ip,
            "callerSuppliedUserAgent": user_agent,
            "requestAttributes": {
                "time": event_time,
                "auth": {},
            },
            "destinationAttributes": {},
        },
        "serviceName": service_name,
        "methodName": method_name,
        "authorizationInfo": [
            {
                "resource": resource_name,
                "permission": authorization_permission or f"{service_name.replace('.googleapis.com','')}.{event_short}",
                "granted": authorization_granted,
                "resourceAttributes": {
                    "service": service_name,
                    "name": resource_name,
                    "type": resource_type,
                },
            }
        ],
        "resourceName": resource_name,
        "request": request_payload or {},
        "response": response_payload or {},
    }

    return {
        # Multicloud wrapper tags (not part of raw GCP audit)
        "cloudProvider": "GCP",
        "log_source_identifier": "GCP Cloud Audit Logs",
        # Real Google Cloud LogEntry envelope
        "insertId": insert_id,
        "logName": f"projects/{project_id}/logs/cloudaudit.googleapis.com%2F{log_type}",
        "resource": {
            "type": resource_type,
            "labels": resource_labels,
        },
        "severity": severity,
        "timestamp": event_time,
        "receiveTimestamp": event_time,
        "labels": {},
        "operation": None,
        "protoPayload": proto_payload,
        # OCL display-name parallel columns
        "Log Source": "GCP Cloud Audit Logs",
        "Event Name": event_short,
        "Method Name": method_name,
        "Service Name": service_name,
        "User Name": principal_email,
        "Principal Email": principal_email,
        "Source IP": caller_ip,
        "Client IP": caller_ip,
        "Project ID": project_id,
        "Resource Name": resource_name,
        "Resource Type": resource_type,
        "Severity": severity,
        "Status Code": str(status_code),
    }
