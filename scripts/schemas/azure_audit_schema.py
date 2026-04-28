"""Canonical Azure Entra ID audit / sign-in schema builders.

Aligns with the Azure Monitor diagnostic-settings export format (the shape
produced when Entra ID audit/sign-in logs are routed through Event Hubs or
Storage Account into OCI Log Analytics). Verified against Microsoft Graph
`/v1.0/auditLogs/directoryAudits` response on 2026-04-24 and the published
Azure Monitor Activity Log schema.

Two categories share the common envelope:
    - SignInLogs: interactive/non-interactive user sign-ins
    - AuditLogs:  directory audit (admin actions, user management)

Common envelope (top-level, camelCase):
    time, resourceId, operationName, operationVersion, category, tenantId,
    resultType, resultSignature, resultDescription, durationMs,
    callerIpAddress, correlationId, identity, Level, location, properties

OCI Log Analytics parsed display-name columns added at ingest:
    'Log Source', 'Event Name', 'User Name', 'Source IP', 'Client IP',
    'Tenant ID', 'Result Type', 'Correlation ID'
"""

from __future__ import annotations

import uuid
from typing import Any


def build_azure_signin_event(
    *,
    event_time: str,
    tenant_id: str,
    user_principal_name: str,
    user_display_name: str,
    user_id: str,
    app_id: str,
    app_display_name: str,
    ip_address: str,
    result_type: str = "0",
    result_signature: str = "None",
    result_description: str = "",
    is_interactive: bool = True,
    client_app_used: str = "Browser",
    country: str = "US",
    city: str = "Redmond",
    state: str = "WA",
    risk_level: str = "none",
    conditional_access_status: str = "notApplied",
    failure_reason: str = "",
    device_os: str = "Windows10",
    device_browser: str = "Edge 120.0.0",
) -> dict[str, Any]:
    """Build an Entra ID SignInLogs event matching Azure Monitor export format."""
    correlation_id = str(uuid.uuid4())
    signin_id = str(uuid.uuid4())
    status_code = int(result_type) if result_type.isdigit() else 0
    operation_name = "Sign-in activity"

    properties: dict[str, Any] = {
        "id": signin_id,
        "createdDateTime": event_time,
        "userDisplayName": user_display_name,
        "userPrincipalName": user_principal_name,
        "userId": user_id,
        "appId": app_id,
        "appDisplayName": app_display_name,
        "ipAddress": ip_address,
        "clientAppUsed": client_app_used,
        "correlationId": correlation_id,
        "conditionalAccessStatus": conditional_access_status,
        "isInteractive": is_interactive,
        "riskDetail": "none",
        "riskLevelAggregated": risk_level,
        "riskLevelDuringSignIn": risk_level,
        "riskState": "none",
        "riskEventTypes": [],
        "resourceDisplayName": app_display_name,
        "resourceId": app_id,
        "status": {
            "errorCode": status_code,
            "failureReason": failure_reason or ("Other." if status_code else ""),
            "additionalDetails": "",
        },
        "deviceDetail": {
            "deviceId": "",
            "displayName": "",
            "operatingSystem": device_os,
            "browser": device_browser,
            "isCompliant": None,
            "isManaged": None,
            "trustType": "",
        },
        "location": {
            "city": city,
            "state": state,
            "countryOrRegion": country,
            "geoCoordinates": {"altitude": None, "latitude": 0.0, "longitude": 0.0},
        },
        "appliedConditionalAccessPolicies": [],
    }

    return {
        "cloudProvider": "Azure",
        "log_source_identifier": "Azure Entra ID Sign-in Logs",
        "time": event_time,
        "resourceId": f"/tenants/{tenant_id}/providers/Microsoft.aadiam",
        "operationName": operation_name,
        "operationVersion": "1.0",
        "category": "SignInLogs",
        "tenantId": tenant_id,
        "resultType": result_type,
        "resultSignature": result_signature,
        "resultDescription": result_description,
        "durationMs": 0,
        "callerIpAddress": ip_address,
        "correlationId": correlation_id,
        "identity": user_display_name,
        "Level": 4,
        "location": country,
        "properties": properties,
        "Log Source": "Azure Entra ID Sign-in Logs",
        "Event Name": operation_name,
        "User Name": user_principal_name,
        "Source IP": ip_address,
        "Client IP": ip_address,
        "Tenant ID": tenant_id,
        "Result Type": result_type,
        "Correlation ID": correlation_id,
        "Country": country,
        "App Name": app_display_name,
    }


def build_azure_audit_event(
    *,
    event_time: str,
    tenant_id: str,
    operation_type: str,
    activity_display_name: str,
    category: str,
    initiator_upn: str,
    initiator_id: str,
    initiator_ip: str,
    target_resource_type: str = "User",
    target_resource_name: str = "",
    target_resource_upn: str = "",
    modified_properties: list[dict[str, str]] | None = None,
    result: str = "success",
    result_reason: str = "",
    logged_by_service: str = "Core Directory",
) -> dict[str, Any]:
    """Build an Entra ID AuditLogs event matching Azure Monitor export format."""
    correlation_id = str(uuid.uuid4())
    audit_id = str(uuid.uuid4())
    operation_name = activity_display_name

    properties: dict[str, Any] = {
        "id": audit_id,
        "category": category,
        "correlationId": correlation_id,
        "result": result,
        "resultReason": result_reason,
        "activityDisplayName": activity_display_name,
        "activityDateTime": event_time,
        "loggedByService": logged_by_service,
        "operationType": operation_type,
        "initiatedBy": {
            "user": {
                "id": initiator_id,
                "displayName": initiator_upn.split("@")[0],
                "userPrincipalName": initiator_upn,
                "ipAddress": initiator_ip,
                "roles": [],
            },
            "app": None,
        },
        "targetResources": [
            {
                "id": str(uuid.uuid4()),
                "displayName": target_resource_name,
                "type": target_resource_type,
                "userPrincipalName": target_resource_upn or None,
                "groupType": None,
                "modifiedProperties": modified_properties or [],
            }
        ],
        "additionalDetails": [],
    }

    result_type = "0" if result == "success" else "1"

    return {
        "cloudProvider": "Azure",
        "log_source_identifier": "Azure Entra ID Audit Logs",
        "time": event_time,
        "resourceId": f"/tenants/{tenant_id}/providers/Microsoft.aadiam",
        "operationName": operation_name,
        "operationVersion": "1.0",
        "category": "AuditLogs",
        "tenantId": tenant_id,
        "resultType": result_type,
        "resultSignature": "None",
        "resultDescription": result_reason,
        "durationMs": 0,
        "callerIpAddress": initiator_ip,
        "correlationId": correlation_id,
        "identity": initiator_upn.split("@")[0],
        "Level": 4,
        "location": "global",
        "properties": properties,
        "Log Source": "Azure Entra ID Audit Logs",
        "Event Name": activity_display_name,
        "User Name": initiator_upn,
        "Source IP": initiator_ip,
        "Client IP": initiator_ip,
        "Tenant ID": tenant_id,
        "Result Type": result_type,
        "Correlation ID": correlation_id,
        "Operation": activity_display_name,
        "Workload": "AzureActiveDirectory",
        "Target UPN": target_resource_upn,
        "Target Type": target_resource_type,
    }


def build_azure_activity_event(
    *,
    event_time: str,
    subscription_id: str,
    tenant_id: str,
    caller: str,
    caller_ip: str,
    operation_name: str,
    resource_provider: str,
    resource_group: str,
    resource_id: str,
    status: str = "Succeeded",
    action: str = "",
) -> dict[str, Any]:
    """Build an Azure Activity Log (ARM) event matching the subscription-scoped schema."""
    correlation_id = str(uuid.uuid4())
    event_id = str(uuid.uuid4())
    op_short = operation_name.split("/")[-1] if "/" in operation_name else operation_name

    return {
        "cloudProvider": "Azure",
        "log_source_identifier": "Azure Activity Logs",
        "authorization": {
            "action": action or operation_name,
            "scope": resource_id,
            "evidence": {"role": "Contributor", "roleAssignmentScope": f"/subscriptions/{subscription_id}"},
        },
        "caller": caller,
        "channels": "Operation",
        "claims": {},
        "correlationId": correlation_id,
        "description": "",
        "eventDataId": event_id,
        "eventName": {"value": "EndRequest", "localizedValue": "End request"},
        "category": {"value": "Administrative", "localizedValue": "Administrative"},
        "eventTimestamp": event_time,
        "id": f"/subscriptions/{subscription_id}/events/{event_id}/ticks/0",
        "level": "Informational",
        "operationId": str(uuid.uuid4()),
        "operationName": {"value": operation_name, "localizedValue": op_short},
        "resourceGroupName": resource_group,
        "resourceProviderName": {"value": resource_provider, "localizedValue": resource_provider},
        "resourceType": {"value": resource_provider, "localizedValue": resource_provider},
        "resourceId": resource_id,
        "status": {"value": status, "localizedValue": status},
        "subStatus": {"value": "", "localizedValue": ""},
        "submissionTimestamp": event_time,
        "subscriptionId": subscription_id,
        "tenantId": tenant_id,
        "properties": {},
        "httpRequest": {
            "clientRequestId": str(uuid.uuid4()),
            "clientIpAddress": caller_ip,
            "method": "PUT",
            "uri": f"https://management.azure.com{resource_id}",
        },
        "Log Source": "Azure Activity Logs",
        "Event Name": op_short,
        "User Name": caller,
        "Source IP": caller_ip,
        "Client IP": caller_ip,
        "Tenant ID": tenant_id,
        "Subscription ID": subscription_id,
        "Resource Group": resource_group,
        "Resource Provider": resource_provider,
        "Operation": operation_name,
        "Result Type": status,
        "Correlation ID": correlation_id,
    }
