"""Baseline application and browser synthetic event batches."""

from testlogs.common import *  # noqa: F401,F403
from testlogs.application_core import application_event


def _baseline_application_events():
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


    return events
