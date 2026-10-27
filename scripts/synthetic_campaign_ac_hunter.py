"""Synthetic storyline ac hunter event family.

Explicit inputs preserve deterministic identities and caller-controlled event order.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

if __package__:
    from .synthetic_campaign_common import (
        _format_iso_utc,
    )
else:
    from synthetic_campaign_common import (
        _format_iso_utc,
    )


def build_network_hunt_events(
    *,
    rmm_relay_ip: str,
    base_date: dt.date,
    d1_ts1: str,
    d4_ts2: str,
    d5_ts3: str,
    d6_ts2: str,
    d7_trace: str,
    d7_ts1: str,
    d7_ts2: str,
    d7_ts3: str,
    day_traces: dict[int, str],
    dns_domain: str,
    guardian_adb: str,
    ip_goad_dc: str,
    ip_goad_dc2: str,
    ip_goad_pivot: str,
    ip_oke_node: str,
    ip_vcn_target: str,
    observeai_adb: str,
    prefix: str,
) -> list[dict[str, Any]]:
    """Emit this event family using the supplied identities and timeline."""
    # 6. AC-Hunter Network Threat Hunting Telemetry (Capabilities 01 through 08)
    ac_hunter_telemetry: list[dict[str, Any]] = []

    # (a) Capability 01: C2 Beaconing (RITA Interval Histogram & Skew Score — 60s ± 1s intervals)
    beacon_hosts = [
        ("kingslanding", ip_goad_dc, "198.51.100.214", "8443", 3, 96.4, 384),
        ("winterfell", ip_goad_dc2, "198.51.100.214", "8443", 4, 95.8, 384),
        ("castelblack", ip_goad_pivot, rmm_relay_ip, "7844", 4, 91.8, 512),
        (f"{prefix}-oke-worker-01", ip_oke_node, "198.51.100.214", "8443", 5, 96.4, 384),
    ]
    beacon_intervals = (60, 59, 61, 60, 60, 59)
    for host_name, src_ip_val, dst_ip_val, dst_port_val, b_day, rita_score, pkt_bytes in beacon_hosts:
        b_date = base_date + dt.timedelta(days=b_day - 1)
        b_cursor = dt.datetime.combine(b_date, dt.time(15, 0, 0), tzinfo=dt.timezone.utc)
        for pulse_idx, delta_sec in enumerate(beacon_intervals, start=1):
            b_cursor = b_cursor + dt.timedelta(seconds=delta_sec)
            pulse_ts = _format_iso_utc(b_cursor)
            ac_hunter_telemetry.append({
                "time": pulse_ts,
                "timestamp": pulse_ts,
                "day": b_day,
                "stage_id": f"STORYLINE-DAY-0{b_day}",
                "record_category": "ac_hunter_network_telemetry",
                "ac_hunter_module": "c2_beaconing_rita",
                "Log Source": "SOC VCN Flow Logs",
                "Host Name": host_name,
                "Source IP": src_ip_val,
                "Destination IP": dst_ip_val,
                "Source Port": str(51200 + pulse_idx),
                "Destination Port": dst_port_val,
                "Protocol": "6",
                "Action": "ACCEPT",
                "Network Action": "ACCEPT",
                "Bytes Sent": pkt_bytes,
                "Bytes Received": 192,
                "Packets": 4,
                "rita_beacon_score": rita_score,
                "beacon_interval_sec": delta_sec,
                "beacon_jitter_pct": 1.6,
                "Flow ID": f"ac-hunter-rita-{host_name}-d{b_day}-p{pulse_idx}",
                "Trace ID": day_traces[b_day],
                "msg": f"AC-Hunter rita_beacon pulse #{pulse_idx} score={rita_score} interval={delta_sec}s (60s±1s) from {host_name} ({src_ip_val}) to {dst_ip_val}:{dst_port_val}",
            })
        # Summary analytical row in SOC Application Logs for RITA beacon detector
        ac_hunter_telemetry.append({
            "time": _format_iso_utc(b_cursor),
            "timestamp": _format_iso_utc(b_cursor),
            "day": b_day,
            "stage_id": f"STORYLINE-DAY-0{b_day}",
            "record_category": "ac_hunter_network_telemetry",
            "ac_hunter_module": "c2_beaconing_rita",
            "Log Source": "SOC Application Logs",
            "Service Name": "ac-hunter-rita-analyzer",
            "Host Name": host_name,
            "Source IP": src_ip_val,
            "Client IP": src_ip_val,
            "Destination IP": dst_ip_val,
            "Destination Port": dst_port_val,
            "Network Bytes Out": pkt_bytes * len(beacon_intervals),
            "Response Code": "200",
            "Attack Stage": "c2_beaconing_rita",
            "Attack Type": "periodic_c2_heartbeat",
            "MITRE Technique ID": "T1071.001",
            "MITRE Tactic": "Command and Control",
            "rita_beacon_score": rita_score,
            "Trace ID": day_traces[b_day],
            "msg": f"AC-Hunter rita_beacon confirmed periodic C2 heartbeat score={rita_score} interval=60s±1s from {host_name} ({src_ip_val}) to {dst_ip_val}:{dst_port_val}",
        })

    # (b) Capability 02: Long Connections (Duration > 3600s)
    for lc_day, lc_ts, lc_host, lc_src, lc_dst, lc_port, lc_dur, lc_bytes, lc_proto_label in [
        (4, d4_ts2, "castelblack", ip_goad_pivot, rmm_relay_ip, "7844", 14820, 18450000, "cloudflared-rmm-tunnel"),
        (7, d7_ts2, "kingslanding", ip_vcn_target, "198.51.100.214", "8443", 28400, 52428800, "persistent-tls-c2-exfil"),
    ]:
        ac_hunter_telemetry.append({
            "time": lc_ts,
            "timestamp": lc_ts,
            "day": lc_day,
            "stage_id": f"STORYLINE-DAY-0{lc_day}",
            "record_category": "ac_hunter_network_telemetry",
            "ac_hunter_module": "long_connections",
            "Log Source": "SOC VCN Flow Logs",
            "Host Name": lc_host,
            "Source IP": lc_src,
            "Destination IP": lc_dst,
            "Source Port": "54918",
            "Destination Port": lc_port,
            "Protocol": "6",
            "Action": "ACCEPT",
            "Network Action": "ACCEPT",
            "Bytes Sent": lc_bytes,
            "Bytes Received": 642000,
            "Packets": 24800,
            "duration_sec": lc_dur,
            "Flow ID": f"ac-hunter-long-conn-{lc_host}-d{lc_day}",
            "Trace ID": day_traces[lc_day],
            "msg": f"AC-Hunter long_connection duration={lc_dur}s ({lc_proto_label}) from {lc_host} ({lc_src}) to {lc_dst}:{lc_port} bytes={lc_bytes}",
        })
        ac_hunter_telemetry.append({
            "time": lc_ts,
            "timestamp": lc_ts,
            "day": lc_day,
            "stage_id": f"STORYLINE-DAY-0{lc_day}",
            "record_category": "ac_hunter_network_telemetry",
            "ac_hunter_module": "long_connections",
            "Log Source": "SOC Application Logs",
            "Service Name": "ac-hunter-long-conn-tracker",
            "Host Name": lc_host,
            "Source IP": lc_src,
            "Client IP": lc_src,
            "Destination IP": lc_dst,
            "Destination Port": lc_port,
            "Network Bytes Out": lc_bytes,
            "Response Code": "200",
            "duration_sec": lc_dur,
            "MITRE Technique ID": "T1572",
            "MITRE Tactic": "Command and Control",
            "Trace ID": day_traces[lc_day],
            "msg": f"AC-Hunter long_connection alert: persistent session duration={lc_dur}s (>3600s threshold) from {lc_host} to {lc_dst}:{lc_port}",
        })

    # (c) Capability 03: DNS Beaconing & Subdomain Entropy (342 distinct subdomains)
    dns_subdomains = [
        "f91a03bc84e27d1190aa45c6e8b2019f.exfil.c2-stage.example.net",
        "c4d8e2a190b77f63512890abcef12345.exfil.c2-stage.example.net",
        "7b3e91c4a0f82d65e11239a8bc4701fe.exfil.c2-stage.example.net",
    ]
    for sub_idx, fqdn_val in enumerate(dns_subdomains, start=1):
        ac_hunter_telemetry.append({
            "time": d7_ts1,
            "timestamp": d7_ts1,
            "TimeCreated": d7_ts1,
            "day": 7,
            "stage_id": "STORYLINE-DAY-07",
            "record_category": "ac_hunter_network_telemetry",
            "ac_hunter_module": "dns_beaconing_fqdn_entropy",
            "Log Source": "SOC Windows Sysmon Logs",
            "Event ID": "22",
            "EventID": "22",
            "Host Name": "kingslanding",
            "Host Name (Server)": "kingslanding",
            "Computer": "kingslanding",
            "User": "NT AUTHORITY\\SYSTEM",
            "Process Name": "C:\\Users\\Public\\splunkd.exe",
            "Query Name": fqdn_val,
            "Query Results": "type: 16 TXT; 198.51.100.214",
            "Destination IP": "198.51.100.214",
            "Destination Port": "53",
            "distinct_subdomain_count": 342,
            "fqdn_shannon_entropy": 4.62,
            "Trace ID": d7_trace,
            "msg": f"AC-Hunter subdomain_entropy=4.62 distinct_subdomains=342 DNS TXT tunneling query #{sub_idx} {fqdn_val} to 198.51.100.214",
        })

    # (d) Capability 04: Client Signatures & TLS JA3/JA4 / User-Agent Profiling
    for cs_day, cs_ts, cs_host, cs_ip, cs_ua, cs_ja3, cs_ja4 in [
        (1, d1_ts1, f"octo-drone-shop.{dns_domain}", "198.51.100.214", "Mozilla/5.0 (compatible; Nuclei/3.3.0; +https://projectdiscovery.io)", "e7d705a3286e19ea42f587b344ee6865", "t13d1516h2_8daaf6152771_b186095e22b6"),
        (5, d5_ts3, guardian_adb, "203.0.113.88", "OCI-Python-SDK/2.126.0 (screenconnect-relay)", "a0e9f5d64349fb13191bc781f81f42e1", "t13d1715h2_5b57614c22b0_3d5424432f57"),
        (6, d6_ts2, observeai_adb, "192.0.2.119", "Go-http-client/1.1 (python-oracledb-agentic-probe)", "72a589da586844d7f0818ce684948eea", "t12d190800_d83cc789557e_16bb6775592a"),
    ]:
        ac_hunter_telemetry.append({
            "time": cs_ts,
            "timestamp": cs_ts,
            "day": cs_day,
            "stage_id": f"STORYLINE-DAY-0{cs_day}",
            "record_category": "ac_hunter_network_telemetry",
            "ac_hunter_module": "client_signatures_ja3",
            "Log Source": "SOC Application Logs",
            "Service Name": "ac-hunter-client-profiler",
            "Host Name": cs_host,
            "Client IP": cs_ip,
            "Source IP": cs_ip,
            "Destination IP": ip_vcn_target,
            "HTTP Method": "POST",
            "Request URL": "/api/v1/tls-fingerprint-telemetry",
            "Response Code": "200",
            "User Agent": cs_ua,
            "ja3_hash": cs_ja3,
            "ja4_fingerprint": cs_ja4,
            "MITRE Technique ID": "T1071.001",
            "MITRE Tactic": "Command and Control",
            "Trace ID": day_traces[cs_day],
            "msg": f"AC-Hunter client_signature anomaly ja3_hash={cs_ja3} ja4={cs_ja4} User-Agent='{cs_ua}' from {cs_ip}",
        })

    # (e) Capability 07: Composite Threat Score (0-100) & Threat Intel / Safelist Correlation
    for ts_day, ts_time, ts_host, ts_src, ts_dst, ts_score, ts_summary in [
        (7, d7_ts3, "kingslanding", ip_goad_dc, "198.51.100.214", 97, "beacon=96.4 long_conn=28400s dns_subdomains=342 dcsync=true"),
        (7, d7_ts3, f"{prefix}-oke-worker-01", ip_oke_node, "198.51.100.214", 94, "oke_imdsv2_breakout=true beacon=96.4 multicloud_aws_pivot=true"),
        (7, d7_ts3, "winterfell", ip_goad_dc2, "198.51.100.214", 92, "amsi_bypass=true kerberoasting_4769=true beacon=95.8"),
        (7, d7_ts3, "castelblack", ip_goad_pivot, rmm_relay_ip, 89, "cloudflared_rmm_tunnel=14820s sharphound=true beacon=91.8"),
    ]:
        ac_hunter_telemetry.append({
            "time": ts_time,
            "timestamp": ts_time,
            "day": ts_day,
            "stage_id": f"STORYLINE-DAY-0{ts_day}",
            "record_category": "ac_hunter_network_telemetry",
            "ac_hunter_module": "composite_threat_score",
            "Log Source": "SOC Application Logs",
            "Service Name": "ac-hunter-scoring-engine",
            "Host Name": ts_host,
            "Source IP": ts_src,
            "Client IP": ts_src,
            "Destination IP": ts_dst,
            "Destination Port": "8443" if ts_dst == "198.51.100.214" else "7844",
            "Response Code": "200",
            "composite_threat_score": ts_score,
            "safelist_disposition": "NOT_SAFELISTED_MALICIOUS_IOC",
            "MITRE Technique ID": "T1071",
            "MITRE Tactic": "Command and Control",
            "Trace ID": day_traces[ts_day],
            "msg": f"AC_HUNTER_SCORE={ts_score}/100 host={ts_host} src={ts_src} dst={ts_dst} safelist=FAIL indicators=[{ts_summary}]",
        })
    return ac_hunter_telemetry
