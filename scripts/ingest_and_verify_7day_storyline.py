#!/usr/bin/env python3.11
"""Live Multi-Pillar Ingestion & Query Verification for the 7-Day Threat Hunting Storyline.

1. Uploads the 7-day multi-source storyline logs (background tasks + 7-day attack kill chain)
   into OCI Log Analytics (`oci-demo-csp-logs` log group) per `Log Source`.
2. Emits correlated custom metrics into OCI Monitoring (`oci_observability_demo` and `octo_security_melts`).
3. Emits OpenTelemetry / Zipkin spans into OCI APM and AI Agent MELTS reasoning traces/spans
   (`logan.execute_query`, `apm.query_traces`, `monitoring.summarize_metrics`,
   `datasafe.audit_events`, `caldera.operation_correlation`) into Langfuse (`lf.<DNS_DOMAIN>`).
4. Executes live OCI Log Analytics `query` API verification across all 7 storyline hunting queries
   and all 2026 Threat Report pack queries to prove 100% clean parse & execution.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import io
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from generate_synthetic_2026_campaign import (  # noqa: E402
    SEVEN_DAY_KILL_CHAIN_DAYS,
    generate_7day_storyline_bundle,
)


def _load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _resolve_k8s_apm_credentials(env: dict[str, str]) -> tuple[str, str]:
    endpoint = env.get("OCI_APM_ENDPOINT", "")
    datakey = env.get("OCI_APM_PRIVATE_DATAKEY") or env.get("OCI_APM_PUBLIC_DATAKEY", "")
    if endpoint and datakey:
        return endpoint, datakey
    try:
        cm_out = subprocess.check_output(
            ["kubectl", "get", "configmap", "-n", "observeai", "observeai-config", "-o", "jsonpath={.data.OCI_APM_ENDPOINT}"],
            text=True,
            timeout=10,
        ).strip()
        if cm_out:
            endpoint = cm_out
        sec_out = subprocess.check_output(
            ["kubectl", "get", "secret", "-n", "observeai", "observeai-config-secret", "-o", "jsonpath={.data.OCI_APM_PRIVATE_DATAKEY}"],
            text=True,
            timeout=10,
        ).strip()
        if sec_out:
            datakey = base64.b64decode(sec_out).decode("utf-8").strip()
    except Exception:
        pass
    return endpoint, datakey


def _ensure_log_group(
    la_client: Any,
    namespace: str,
    compartment_id: str,
    candidate_compartments: list[str] | None = None,
    display_name: str = "oci-demo-csp-logs",
) -> str:
    import oci

    for cid in [compartment_id, *(candidate_compartments or [])]:
        if not cid:
            continue
        items = la_client.list_log_analytics_log_groups(
            namespace_name=namespace,
            compartment_id=cid,
            display_name=display_name,
        ).data.items
        if items:
            return items[0].id
    created = la_client.create_log_analytics_log_group(
        namespace_name=namespace,
        create_log_analytics_log_group_details=oci.log_analytics.models.CreateLogAnalyticsLogGroupDetails(
            compartment_id=compartment_id,
            display_name=display_name,
            description="OCI-DEMO 7-Day Multi-Pillar Threat Hunting & CSP Logs",
        ),
    ).data
    return created.id


def ingest_log_analytics(
    la_client: Any,
    namespace: str,
    log_group_id: str,
    logs: list[dict[str, Any]],
) -> dict[str, Any]:
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in logs:
        source_name = row.get("Log Source") or row.get("log_source") or "SOC Application Logs"
        by_source[source_name].append(row)

    uploaded_sources: dict[str, int] = {}
    errors: dict[str, str] = {}
    for source_name, rows in sorted(by_source.items()):
        ndjson_bytes = ("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n").encode("utf-8")
        slug = source_name.lower().replace(" ", "-")
        try:
            la_client.upload_log_file(
                namespace_name=namespace,
                log_source_name=source_name,
                filename=f"storyline-7day-{slug}.jsonl",
                opc_meta_loggrpid=log_group_id,
                upload_log_file_body=io.BytesIO(ndjson_bytes),
                content_type="application/octet-stream",
            )
            uploaded_sources[source_name] = len(rows)
        except Exception as exc:
            errors[source_name] = str(exc)[:200]
    return {
        "namespace": namespace,
        "log_group_detected": bool(log_group_id),
        "uploaded_sources": uploaded_sources,
        "total_uploaded_records": sum(uploaded_sources.values()),
        "errors": errors,
    }


def emit_oci_monitoring_metrics(
    cfg: dict[str, Any],
    compartment_id: str,
    metrics: list[dict[str, Any]],
    multicloud_metrics: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    import oci

    region = cfg.get("region", "eu-frankfurt-1")
    endpoint = f"https://telemetry-ingestion.{region}.oraclecloud.com"
    mon_client = oci.monitoring.MonitoringClient(cfg, service_endpoint=endpoint)
    now = dt.datetime.now(dt.timezone.utc)
    metric_details = []
    # OCI Monitoring reserves the `oci_` prefix for Oracle system namespaces; custom namespaces use `octo_*`.
    custom_namespaces = ["octo_security_melts", "octo_observability_demo"]
    for idx, m in enumerate(metrics):
        point_ts = now - dt.timedelta(minutes=(len(metrics) - idx) * 5)
        dims = {str(k): str(v) for k, v in (m.get("dimensions") or {}).items()}
        dims["storyline_timestamp"] = str(m.get("timestamp", ""))
        for ns in custom_namespaces:
            metric_details.append(
                oci.monitoring.models.MetricDataDetails(
                    namespace=ns,
                    compartment_id=compartment_id,
                    name=m["name"],
                    dimensions=dims,
                    datapoints=[
                        oci.monitoring.models.Datapoint(
                            timestamp=point_ts,
                            value=float(m["value"]),
                            count=1,
                        )
                    ],
                )
            )
    mc_list = list(multicloud_metrics or [])
    for idx, m in enumerate(mc_list):
        point_ts = now - dt.timedelta(minutes=(len(mc_list) - idx) * 3)
        dims = {str(k): str(v) for k, v in (m.get("dimensions") or {}).items()}
        dims["storyline_timestamp"] = str(m.get("timestamp", ""))
        primary_ns = m.get("namespace", "octo_multicloud_ops")
        if primary_ns.startswith("oci_"):
            primary_ns = "octo_" + primary_ns[4:]
        for ns in (primary_ns, "octo_observability_demo"):
            metric_details.append(
                oci.monitoring.models.MetricDataDetails(
                    namespace=ns,
                    compartment_id=compartment_id,
                    name=m["name"],
                    dimensions=dims,
                    datapoints=[
                        oci.monitoring.models.Datapoint(
                            timestamp=point_ts,
                            value=float(m["value"]),
                            count=1,
                        )
                    ],
                )
            )
    resp = mon_client.post_metric_data(
        post_metric_data_details=oci.monitoring.models.PostMetricDataDetails(
            metric_data=metric_details,
            batch_atomicity="NON_ATOMIC",
        )
    ).data
    failed_count = getattr(resp, "failed_metrics_count", 0) or 0
    return {
        "namespaces": ["octo_security_melts", "octo_observability_demo", "octo_multicloud_ops", "octo_ac_hunter"],
        "submitted_streams": len(metric_details),
        "failed_metrics_count": failed_count,
        "status": "ok" if failed_count == 0 else "partial",
    }


def emit_oci_apm_traces(
    endpoint: str,
    datakey: str,
    apm_traces: list[dict[str, Any]],
) -> dict[str, Any]:
    if not endpoint or not datakey:
        return {"status": "skipped", "reason": "missing_apm_endpoint_or_datakey"}
    url = f"{endpoint.rstrip('/')}/20200101/observations/private-span?dataFormat=zipkin&dataFormatVersion=2&dataKey={datakey}"
    now_us = int(time.time() * 1_000_000)
    zipkin_spans = []
    for idx, span in enumerate(apm_traces):
        dur_us = int(span.get("duration_ms", 200)) * 1000
        start_us = now_us - (len(apm_traces) - idx) * 500_000
        tags = {str(k): str(v) for k, v in (span.get("attributes") or {}).items()}
        tags["otel.status_code"] = str(span.get("status", "OK"))
        record: dict[str, Any] = {
            "traceId": span["trace_id"],
            "id": span["span_id"],
            "name": span["operation_name"],
            "timestamp": start_us,
            "duration": dur_us,
            "localEndpoint": {"serviceName": span.get("service_name", "observeai-coordinator-agent")},
            "tags": tags,
        }
        if span.get("parent_span_id"):
            record["parentId"] = span["parent_span_id"]
        zipkin_spans.append(record)

    req = urllib.request.Request(
        url,
        data=json.dumps(zipkin_spans).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return {
                "status": "ok",
                "http_status": resp.status,
                "spans_emitted": len(zipkin_spans),
                "trace_id": apm_traces[0]["trace_id"] if apm_traces else "",
            }
    except urllib.error.HTTPError as exc:
        return {"status": "error", "http_status": exc.code, "error": exc.read().decode("utf-8", errors="replace")[:200]}
    except Exception as exc:
        return {"status": "error", "error": str(exc)[:200]}


def _resolve_k8s_langfuse_credentials(env: dict[str, str]) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    for ns, sec in [("observeai", "observeai-secret"), ("oci-ai", "coordinator-langfuse-demo")]:
        try:
            out = subprocess.check_output(
                ["kubectl", "get", "secret", "-n", ns, sec, "-o", "json"],
                text=True,
                timeout=10,
            )
            data = json.loads(out).get("data", {})
            pk = base64.b64decode(data.get("LANGFUSE_PUBLIC_KEY", "")).decode("utf-8", errors="replace").strip()
            sk = base64.b64decode(data.get("LANGFUSE_SECRET_KEY", "")).decode("utf-8", errors="replace").strip()
            if pk and sk and (pk, sk) not in candidates:
                candidates.append((pk, sk))
        except Exception:
            pass
    env_pk = env.get("LANGFUSE_PUBLIC_KEY", "").strip()
    env_sk = env.get("LANGFUSE_SECRET_KEY", "").strip()
    if env_pk and env_sk and (env_pk, env_sk) not in candidates:
        candidates.append((env_pk, env_sk))
    return candidates


def emit_langfuse_traces(
    base_url: str,
    public_key: str,
    secret_key: str,
    langfuse_traces: list[dict[str, Any]],
    extra_keypairs: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    keypairs = list(extra_keypairs or [])
    if public_key and secret_key and (public_key, secret_key) not in keypairs:
        keypairs.append((public_key, secret_key))
    if not base_url or not keypairs:
        return {"status": "skipped", "reason": "missing_langfuse_credentials"}
    url = f"{base_url.rstrip('/')}/api/public/ingestion"
    now = dt.datetime.now(dt.timezone.utc)
    batch: list[dict[str, Any]] = []
    for tr in langfuse_traces:
        tr_time = (now - dt.timedelta(seconds=30)).isoformat()
        batch.append({
            "id": f"evt-trace-{tr['trace_id'][:16]}",
            "type": "trace-create",
            "timestamp": tr_time,
            "body": {
                "id": tr["trace_id"],
                "timestamp": tr_time,
                "name": tr["name"],
                "userId": tr["user_id"],
                "sessionId": tr["session_id"],
                "tags": tr["tags"],
                "input": tr["input"],
                "output": tr["output"],
                "metadata": {
                    "storyline": "7-Day Multi-Pillar Threat Hunting & Caldera/GOAD Emulation",
                    "pillars": ["OCI Log Analytics", "OCI APM", "OCI Monitoring", "Oracle Data Safe", "Caldera/GOAD"],
                },
            },
        })
        for idx, sp in enumerate(tr.get("spans", []), start=1):
            sp_start = now - dt.timedelta(seconds=30 - idx * 4)
            sp_end = sp_start + dt.timedelta(milliseconds=int(sp.get("duration_ms", 250)))
            batch.append({
                "id": f"evt-span-{sp['span_id']}",
                "type": "span-create",
                "timestamp": sp_start.isoformat(),
                "body": {
                    "id": sp["span_id"],
                    "traceId": tr["trace_id"],
                    "name": sp["name"],
                    "startTime": sp_start.isoformat(),
                    "endTime": sp_end.isoformat(),
                    "input": sp["input"],
                    "output": sp["output"],
                    "metadata": {"step_index": sp["step_index"], "melts_tool": sp["name"]},
                },
            })

    last_err: dict[str, Any] = {"status": "error", "error": "no_keypairs_succeeded"}
    for pk, sk in keypairs:
        auth = base64.b64encode(f"{pk}:{sk}".encode("utf-8")).decode("ascii")
        req = urllib.request.Request(
            url,
            data=json.dumps({"batch": batch}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {auth}",
                "User-Agent": "oci-demo-storyline-ingester/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                resp_body = json.loads(resp.read().decode("utf-8", errors="replace") or "{}")
                return {
                    "status": "ok",
                    "http_status": resp.status,
                    "events_submitted": len(batch),
                    "trace_ids": [t["trace_id"] for t in langfuse_traces],
                    "errors": resp_body.get("errors", []),
                }
        except urllib.error.HTTPError as exc:
            last_err = {
                "status": "error",
                "http_status": exc.code,
                "error": exc.read().decode("utf-8", errors="replace")[:200],
            }
        except Exception as exc:
            last_err = {"status": "error", "error": str(exc)[:200]}
    return last_err


def verify_live_queries(
    la_client: Any,
    namespace: str,
    compartment_id: str,
) -> dict[str, Any]:
    import oci

    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(days=14)
    queries_to_verify: list[tuple[str, str]] = []

    # 1. All 7 storyline hunting queries
    for day_meta in SEVEN_DAY_KILL_CHAIN_DAYS:
        q_path = ROOT / "queries" / day_meta["query_file"]
        q_obj = json.loads(q_path.read_text(encoding="utf-8"))
        queries_to_verify.append((day_meta["query_file"], q_obj["query"]))

    # 1b. All 8 AC-Hunter Network Hunting pack queries
    ac_manifest_path = ROOT / "packs" / "ac_hunter_network_hunting" / "manifest.json"
    if ac_manifest_path.is_file():
        ac_manifest = json.loads(ac_manifest_path.read_text(encoding="utf-8"))
        for cap in ac_manifest.get("capabilities_replicated", []):
            q_rel = cap["query_file"]
            q_obj = json.loads((ROOT / "queries" / q_rel).read_text(encoding="utf-8"))
            queries_to_verify.append((q_rel, q_obj["query"]))

    # 2. All 2026 Threat Report YAML pack queries
    for pack_path in sorted((ROOT / "packs" / "2026_threat_reports").glob("*.yaml")):
        doc = yaml.safe_load(pack_path.read_text(encoding="utf-8"))
        items = doc.get("detections") or doc.get("campaigns") or doc.get("hunts") or doc.get("days") or []
        for item in items:
            item_id = item.get("id") or item.get("hunt_id") or f"{pack_path.stem}"
            q_str = item.get("log_analytics_query") or (item.get("execute") or {}).get("log_analytics_query")
            if q_str:
                queries_to_verify.append((f"{pack_path.name}:{item_id}", q_str))

    results = []
    for label, query_str in queries_to_verify:
        try:
            resp = la_client.query(
                namespace_name=namespace,
                query_details=oci.log_analytics.models.QueryDetails(
                    compartment_id=compartment_id,
                    compartment_id_in_subtree=True,
                    query_string=query_str,
                    sub_system="LOG",
                    max_total_count=50,
                    time_filter=oci.log_analytics.models.TimeRange(
                        time_start=start,
                        time_end=now + dt.timedelta(minutes=5),
                        time_zone="UTC",
                    ),
                ),
            )
            items = getattr(resp.data, "items", []) or []
            results.append({"id": label, "status": "OK", "rows": len(items)})
        except Exception as exc:
            results.append({"id": label, "status": "ERROR", "rows": 0, "error": str(exc)[:200]})

    errors = [r for r in results if r["status"] == "ERROR"]
    return {
        "total_verified": len(results),
        "ok_count": len(results) - len(errors),
        "error_count": len(errors),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path("/Users/abirzu/orca/workspaces/OCI-DEMO/prd-017-hybrid-platform-platform-secrets-charts-2/.env.oci4cca.local"),
    )
    parser.add_argument("--seed", default="20260901")
    parser.add_argument("--report-out", type=Path, help="Optional JSON report path")
    args = parser.parse_args()

    import oci

    env = {**os.environ, **_load_env_file(args.env_file)}
    profile = env.get("OCI_CONFIG_PROFILE", "DEFAULT")
    cfg = oci.config.from_file(profile_name=profile)
    la_client = oci.log_analytics.LogAnalyticsClient(cfg)
    tenancy_id = cfg["tenancy"]
    ns_items = la_client.list_namespaces(compartment_id=tenancy_id).data.items
    if not ns_items:
        raise RuntimeError("No Log Analytics namespace found in tenancy")
    namespace = ns_items[0].namespace_name

    comp_obs = env.get("COMP_OBSERVABILITY") or env.get("LZ_PARENT_COMPARTMENT_ID") or tenancy_id
    comp_parent = env.get("LZ_PARENT_COMPARTMENT_ID") or comp_obs

    story = generate_7day_storyline_bundle(seed=args.seed, mask_mode="off")

    # Upload into `oci-demo-csp-logs`, `oci-demo-security-logs`, and `oci-demo-application-logs`
    lg_obs = _ensure_log_group(
        la_client,
        namespace,
        comp_obs,
        candidate_compartments=[comp_parent, tenancy_id],
        display_name="oci-demo-csp-logs",
    )
    la_summary = ingest_log_analytics(la_client, namespace, lg_obs, story["all_logs"])
    extra_log_groups: dict[str, int] = {}
    for lg_name in ("oci-demo-security-logs", "oci-demo-application-logs"):
        try:
            lg_id = _ensure_log_group(
                la_client,
                namespace,
                comp_obs,
                candidate_compartments=[comp_parent, tenancy_id],
                display_name=lg_name,
            )
            sub_res = ingest_log_analytics(
                la_client,
                namespace,
                lg_id,
                story.get("multicloud_logs", []) + story.get("ac_hunter_telemetry", []),
            )
            extra_log_groups[lg_name] = sub_res["total_uploaded_records"]
        except Exception:
            pass
    la_summary["extra_log_groups_uploaded"] = extra_log_groups

    mon_summary = emit_oci_monitoring_metrics(
        cfg,
        comp_parent,
        story["metrics"],
        multicloud_metrics=story.get("multicloud_metrics", []),
    )
    apm_endpoint, apm_datakey = _resolve_k8s_apm_credentials(env)
    apm_summary = emit_oci_apm_traces(apm_endpoint, apm_datakey, story["apm_traces"])
    lf_summary = emit_langfuse_traces(
        env.get("LANGFUSE_BASE_URL", ""),
        env.get("LANGFUSE_PUBLIC_KEY", ""),
        env.get("LANGFUSE_SECRET_KEY", ""),
        story["langfuse_traces"],
        extra_keypairs=_resolve_k8s_langfuse_credentials(env),
    )
    query_summary = verify_live_queries(la_client, namespace, tenancy_id)

    report = {
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "storyline_counts": story["storyline_counts"],
        "distinct_dates": story["distinct_dates"],
        "log_analytics_ingestion": la_summary,
        "monitoring_ingestion": mon_summary,
        "apm_ingestion": apm_summary,
        "langfuse_ingestion": lf_summary,
        "live_query_verification": query_summary,
    }
    if args.report_out:
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if query_summary["error_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
