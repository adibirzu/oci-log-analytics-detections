"""Auto-extracted from generate_test_logs.py — application synthetic events.

Behavior-preserving split: function bodies are unchanged. Shared constants and
helpers live in ``testlogs.common`` and are imported via star import.
"""
import json
import ntpath
import os
import random
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testlogs.common import *  # noqa: F401,F403


def _service_namespace_for(service_name):
    octo_services = {
        "enterprise-crm-portal",
        "octo-apm-demo",
        "octo-drone-shop",
        "octo-java-app-server",
        "octo-workflow-gateway",
    }
    return "octo" if service_name in octo_services else "security-lab"


def _service_version_for(service_name):
    versions = {
        "enterprise-crm-portal": "1.1.0",
        "octo-drone-shop": "1.2.0",
        "octo-apm-demo": "1.0.0",
        "octo-java-app-server": "1.0.0",
    }
    return versions.get(service_name, "1.0.0")


def _app_brand_for(service_name):
    brands = {
        "enterprise-crm-portal": "OCTO CRM APM",
        "octo-drone-shop": "OCTO Drone Shop",
        "octo-apm-demo": "OCTO APM Demo",
        "octo-java-app-server": "OCTO Java APM Demo",
    }
    return brands.get(service_name, service_name)


def _workflow_for_path(path):
    normalized = path.split("?", 1)[0]
    if normalized.startswith("/octo/internal/inventory"):
        return "checkout", "inventory"
    if normalized.startswith("/octo/internal/payment"):
        return "checkout", "payment"
    if normalized.startswith("/octo/internal/audit"):
        return "checkout", "audit"
    if normalized.startswith("/octo/checkout") or normalized.startswith("/shop/checkout"):
        return "checkout", "entry"
    if normalized.startswith("/octo/internal/auth"):
        return "auth", "credentials"
    if normalized.startswith("/octo/login"):
        return "auth", "login"
    if normalized.startswith("/octo/metrics"):
        return "observability", "metrics"
    if "/orders/sync" in normalized:
        return "order-sync", "sync"
    if "/orders" in normalized:
        return "checkout", "order"
    if "/payments" in normalized or "/payment" in normalized:
        return "checkout", "payment"
    if "/login" in normalized:
        return "auth", "login"
    if "/health" in normalized:
        return "health", "readiness"
    return "other", "unmapped"


def application_event(service_name, message="Request completed", level="INFO",
                      url="/", http_method="GET", status_code="200",
                      response_time_ms=150, client_ip=None, user_agent=None,
                      user=None, trace_id=None, session_id=None,
                      span_name=None, span_attributes="", attack_type=None,
                      attack_severity=None, waf_score=None, db_target=None,
                      error_type=None, slow_request=False, orders_sync_created=0,
                      orders_sync_updated=0, orders_sync_failed=0,
                      orders_sync_source=None, referrer="https://app.example.com/",
                      response_headers="Content-Type: application/json; X-Frame-Options: DENY",
                      content_type="application/json", hostname=None, span_id=None,
                      parent_span_id="", span_kind="SERVER", apm_domain=None,
                      metric_name=None, metric_value=None, metric_unit=None,
                      workflow_id=None, workflow_step=None, request_id=None,
                      service_namespace=None, service_version=None,
                      deployment_environment="production", app_name=None,
                      app_brand=None, app_runtime="python", app_service=None,
                      db_statement=None, db_elapsed_ms=None,
                      db_connection_name=None, db_ocid=None, run_id=None,
                      java_apm_path=None, java_apm_status_code=None,
                      java_apm_latency_ms=None, java_apm_error_type=None,
                      offset=0):
    """Generate application/browser telemetry shaped for the SOC app dashboards."""
    if client_ip is None:
        client_ip = random.choice(CORPORATE_IPS)
    if user_agent is None:
        user_agent = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
        ])
    if user is None:
        user = random.choice(["cersei", "jaime", "tyrion", "arya", "sansa", "jon"])
    if trace_id is None:
        trace_id = f"trace_{uuid.uuid4().hex[:16]}"
    if session_id is None:
        session_id = f"sess_{uuid.uuid4().hex[:12]}"
    if span_name is None:
        span_name = f"HTTP {http_method} {url.split('?', 1)[0]}"
    if hostname is None:
        hostname = "crm-portal-01" if service_name == "enterprise-crm-portal" else "drone-shop-01"
    if span_id is None:
        span_id = f"span_{uuid.uuid4().hex[:16]}"
    if apm_domain is None:
        apm_domain = service_name
    if request_id is None:
        request_id = f"req_{uuid.uuid4().hex[:8]}"
    if service_namespace is None:
        service_namespace = _service_namespace_for(service_name)
    if service_version is None:
        service_version = _service_version_for(service_name)
    if app_name is None:
        app_name = service_name
    if app_brand is None:
        app_brand = _app_brand_for(service_name)
    if app_service is None:
        app_service = service_name
    if workflow_id is None or workflow_step is None:
        inferred_workflow_id, inferred_workflow_step = _workflow_for_path(url)
        workflow_id = workflow_id or inferred_workflow_id
        workflow_step = workflow_step or inferred_workflow_step
    if db_connection_name is None and db_target:
        db_connection_name = "octo_atp_tp"
    if db_elapsed_ms is None and db_target:
        db_elapsed_ms = response_time_ms
    uri_path = url.split("?", 1)[0]

    return {
        "timestamp": ts(offset),
        "serviceName": service_name,
        "service.name": service_name,
        "service.namespace": service_namespace,
        "service.version": service_version,
        "service.instance.id": hostname,
        "deployment.environment": deployment_environment,
        "app.name": app_name,
        "app.brand": app_brand,
        "app.runtime": app_runtime,
        "app.service": app_service,
        "traceId": trace_id,
        "trace_id": trace_id,
        "span_id": span_id,
        "oracleApmTraceId": trace_id,
        "oracleApmSpanId": span_id,
        "traceparent": f"00-{trace_id}-{span_id}-01",
        "httpMethod": http_method,
        "http.method": http_method,
        "http.request.method": http_method,
        "requestUrl": url,
        "uriPath": uri_path,
        "http.url.path": uri_path,
        "queryString": url.split("?", 1)[1] if "?" in url else "",
        "statusCode": str(status_code),
        "http.status_code": int(status_code),
        "http.response.status_code": int(status_code),
        "http_status": int(status_code),
        "responseTimeMs": response_time_ms,
        "http.response_time_ms": response_time_ms,
        "duration_ms": response_time_ms,
        "clientAddress": client_ip,
        "http.client_ip": client_ip,
        "client.address": client_ip,
        "userAgent": user_agent,
        "user_agent.original": user_agent,
        "user": user,
        "sessionId": session_id,
        "requestId": request_id,
        "request_id": request_id,
        "workflow_id": workflow_id,
        "workflow_step": workflow_step,
        "correlation.id": trace_id,
        "run_id": run_id,
        "route": uri_path,
        "contentType": content_type,
        "referrer": referrer,
        "responseHeaders": response_headers,
        "spanName": span_name,
        "spanAttributes": span_attributes,
        "spanId": span_id,
        "parentSpanId": parent_span_id,
        "spanKind": span_kind,
        "apmDomain": apm_domain,
        "metricName": metric_name,
        "metricValue": metric_value,
        "metricUnit": metric_unit,
        "securityAttackType": attack_type,
        "securityAttackSeverity": attack_severity,
        "wafScore": waf_score,
        "dbTarget": db_target,
        "db.target": db_target,
        "db.statement": db_statement,
        "db.elapsed_ms": db_elapsed_ms,
        "db.connection_name": db_connection_name,
        "db.ocid": db_ocid,
        "errorType": error_type,
        "slowRequest": "true" if slow_request else "false",
        "performance.slow_request": bool(slow_request),
        "java_apm.path": java_apm_path,
        "java_apm.status_code": java_apm_status_code,
        "java_apm.latency_ms": java_apm_latency_ms,
        "java_apm.error_type": java_apm_error_type,
        "ordersSyncCreated": orders_sync_created,
        "ordersSyncUpdated": orders_sync_updated,
        "ordersSyncFailed": orders_sync_failed,
        "ordersSyncSource": orders_sync_source,
        "level": level,
        "severity": level,
        "hostname": hostname,
        "message": message,
    }


