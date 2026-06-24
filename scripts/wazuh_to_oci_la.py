"""Forward live Wazuh telemetry into OCI Log Analytics.

Reads GOAD endpoint telemetry from a Wazuh deployment and uploads each document
to the matching OCI Log Analytics custom source, so the same visibility the
Wazuh dashboard provides (MITRE ATT&CK, Vulnerability Detection, System
Inventory, Security Configuration Assessment) is available in OCI LA.

Three input modes:

  * ``--mode indexer`` — pull from the Wazuh **indexer** (OpenSearch) REST API
    via a Point-in-Time + ``search_after`` cursor over a configurable lookback
    window and index pattern. Credentials come from env only:
    ``WAZUH_INDEXER_URL``, ``WAZUH_INDEXER_USER``, ``WAZUH_INDEXER_PASSWORD``.
  * ``--mode file`` — read newline-delimited JSON alerts from ``--file``.
  * ``--mode stdin`` — read newline-delimited JSON alerts from stdin (the shape
    the Wazuh ``integrator``/``integratord`` custom-integration hook pipes as
    alerts fire — see docs/WAZUH_INTEGRATION.md).

Each document is classified (alerts vs vulnerability vs syscollector/inventory
vs sca) by index name and ``rule.groups`` / payload shape, batched per OCI LA
source, and uploaded through the Log Analytics Upload API. Auth, namespace,
log-group and the emdemo production write-guard are reused from oci_config.py
(mirroring scripts/ingest_test_data.py).

Forwarded JSON is passed through unmodified so it matches the ``*_EXAMPLE``
shapes / JSONPaths declared in scripts/logsources/wazuh_sources.py.

Usage::

    # Periodic pull from the indexer (cron / systemd timer on the Wazuh host)
    WAZUH_INDEXER_URL=https://<PLACEHOLDER>:9200 \\
    WAZUH_INDEXER_USER=admin WAZUH_INDEXER_PASSWORD=*** \\
    OCI_PROFILE=cap python3 scripts/wazuh_to_oci_la.py --mode indexer --lookback 15m

    # Dry-run a file without calling OCI
    python3 scripts/wazuh_to_oci_la.py --mode file --file test_data/wazuh_alerts.jsonl --dry-run

    # Real-time integrator hook (alerts on stdin)
    python3 scripts/wazuh_to_oci_la.py --mode stdin
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import time
from collections import defaultdict
from typing import Any, Iterable, Iterator

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oci_config import (  # noqa: E402
    get_la_client,
    get_namespace,
    ensure_log_group,
    resolve_compartment_id,
    require_oci_config,
    list_available_log_sources,
    resolve_source_from_candidates,
    assert_write_allowed,
    ProdWriteGuardError,
)

from obs_logging import get_logger, bind  # noqa: E402

log = get_logger("wazuh_to_oci_la")


def _emit(logger, level: str, msg: str, **fields: Any) -> None:
    """Log a structured event reliably through a (possibly bound) adapter.

    ``logging.LoggerAdapter`` replaces a call-site ``extra=`` with its own
    bound ``context``, so structured fields passed to a bound adapter are
    silently dropped. Re-binding per call folds the fields into ``context``
    where obs_logging renders them as key=value pairs.
    """
    if fields:
        logger = bind(logger, **fields)
    getattr(logger, level)(msg)

# ─── Source classification ───────────────────────────────────────
#
# OCI LA source display names (must match scripts/logsources/wazuh_sources.py
# and exist in the tenancy — create via scripts/setup_log_sources.py).
SOURCE_ALERTS = "SOC Wazuh Alerts"
SOURCE_VULN = "SOC Wazuh Vulnerabilities"
SOURCE_INVENTORY = "SOC Wazuh Inventory"
SOURCE_SCA = "SOC Wazuh SCA"

ALL_SOURCES = (SOURCE_ALERTS, SOURCE_VULN, SOURCE_INVENTORY, SOURCE_SCA)

# Ordered candidate lists so an environment that named a source slightly
# differently still resolves (mirrors ingest_test_data.py behaviour).
SOURCE_CANDIDATES = {
    SOURCE_ALERTS: [SOURCE_ALERTS],
    SOURCE_VULN: [SOURCE_VULN],
    SOURCE_INVENTORY: [SOURCE_INVENTORY],
    SOURCE_SCA: [SOURCE_SCA],
}

# Short suffix used in the per-batch upload_name (OCI surfaces this in
# list_uploads). Keep stable so operators can find the uploads.
SOURCE_UPLOAD_SUFFIX = {
    SOURCE_ALERTS: "alerts",
    SOURCE_VULN: "vuln",
    SOURCE_INVENTORY: "inventory",
    SOURCE_SCA: "sca",
}

# Default index pattern covers all four Wazuh index families.
DEFAULT_INDEX_PATTERN = "wazuh-alerts-*,wazuh-states-*"
DEFAULT_LOOKBACK = "15m"
DEFAULT_BATCH_SIZE = 500
INDEXER_PAGE_SIZE = 1000

# Retry/backoff knobs (named constants — no magic numbers).
MAX_RETRIES = 4
BACKOFF_BASE_SECONDS = 1.5
INDEXER_TIMEOUT_SECONDS = 60
PIT_KEEP_ALIVE = "2m"

_LOOKBACK_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$", re.IGNORECASE)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


# ─── Document classification ─────────────────────────────────────

def _has_group(doc: dict, *needles: str) -> bool:
    """True if any rule.groups entry contains one of the needles."""
    groups = (doc.get("rule") or {}).get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    lowered = [str(g).lower() for g in groups]
    return any(any(n in g for g in lowered) for n in needles)


def classify_document(doc: dict, index_name: str | None = None) -> str:
    """Map a Wazuh document to its OCI LA source display name.

    Resolution order:
      1. Index name (authoritative when present): wazuh-states-vulnerabilities-*,
         wazuh-states-inventory-*, wazuh-alerts-*.
      2. Payload shape: a ``vulnerability`` / ``data.sca`` / syscollector block.
      3. ``rule.groups`` hints (vulnerability-detector, sca, syscollector).
      4. Fallback: alerts (the rule-engine stream).
    """
    idx = (index_name or doc.get("_index") or "").lower()
    if idx:
        if "vulnerabilit" in idx:
            return SOURCE_VULN
        if "inventory" in idx or "syscollector" in idx:
            return SOURCE_INVENTORY
        if "sca" in idx:
            return SOURCE_SCA
        # wazuh-alerts-* (and anything else) falls through to shape checks then alerts.

    # Payload-shape signals (works for integrator/stdin docs with no _index).
    if isinstance(doc.get("vulnerability"), dict):
        return SOURCE_VULN

    data = doc.get("data")
    if isinstance(data, dict):
        if isinstance(data.get("sca"), dict):
            return SOURCE_SCA
        # syscollector inventory: hardware/OS/program blocks under data.*
        if any(k in data for k in ("cpu", "ram", "os", "program", "hotfix", "hardware")):
            # Guard against Windows eventdata docs that also carry data.win.
            if "win" not in data:
                return SOURCE_INVENTORY

    # rule.groups hints.
    if _has_group(doc, "vulnerability-detector", "vulnerability"):
        return SOURCE_VULN
    if _has_group(doc, "sca"):
        return SOURCE_SCA
    if _has_group(doc, "syscollector"):
        return SOURCE_INVENTORY

    return SOURCE_ALERTS


def _unwrap_source(hit_or_doc: dict) -> dict:
    """Return the Wazuh document, unwrapping an OpenSearch hit envelope.

    Indexer hits look like ``{"_index": ..., "_source": {...}, "sort": [...]}``.
    File/stdin docs are already the raw document. We preserve ``_index`` onto
    the unwrapped doc so classification stays index-aware.
    """
    if "_source" in hit_or_doc and isinstance(hit_or_doc["_source"], dict):
        src = dict(hit_or_doc["_source"])
        if "_index" in hit_or_doc and "_index" not in src:
            src["_index"] = hit_or_doc["_index"]
        return src
    return hit_or_doc


# ─── Input: NDJSON (file / stdin) ────────────────────────────────

def iter_ndjson(stream: Iterable[str]) -> Iterator[dict]:
    """Yield parsed JSON objects from newline-delimited JSON lines.

    Invalid lines are logged and skipped rather than aborting the whole run.
    """
    for lineno, raw in enumerate(stream, start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            log.warning("ndjson.skip_invalid", extra={"line": lineno, "error": str(exc)})
            continue
        if isinstance(obj, dict):
            yield _unwrap_source(obj)
        else:
            log.warning("ndjson.skip_non_object", extra={"line": lineno})


def read_file_documents(path: str) -> Iterator[dict]:
    """Yield documents from an NDJSON file path."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Input file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        yield from iter_ndjson(fh)


def read_stdin_documents() -> Iterator[dict]:
    """Yield documents from stdin (NDJSON).

    Supports both a stream of one-JSON-object-per-line (integrator default) and
    a single JSON object piped as one blob (integratord single-alert hook).
    """
    data = sys.stdin.read()
    stripped = data.strip()
    if not stripped:
        return
    # Single JSON object (the integrator hook usually passes one alert file).
    if stripped.startswith("{") and "\n" not in stripped.rstrip("\n"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                yield _unwrap_source(obj)
                return
        except json.JSONDecodeError:
            pass  # fall through to line-by-line
    yield from iter_ndjson(stripped.splitlines())


# ─── Input: Wazuh indexer (OpenSearch) ───────────────────────────

def parse_lookback_seconds(lookback: str) -> int:
    """Convert a lookback like '15m', '2h', '1d', '30s' to seconds."""
    match = _LOOKBACK_RE.match(lookback or "")
    if not match:
        raise ValueError(
            f"Invalid --lookback '{lookback}'. Use <number><s|m|h|d>, e.g. 15m, 2h, 1d."
        )
    value, unit = int(match.group(1)), match.group(2).lower()
    return value * _UNIT_SECONDS[unit]


def _indexer_credentials() -> tuple[str, str, str, bool]:
    """Resolve indexer URL + credentials from env. Never hardcoded.

    Returns (url, user, password, verify_tls). Raises if any are missing.
    """
    url = os.environ.get("WAZUH_INDEXER_URL", "").strip().rstrip("/")
    user = os.environ.get("WAZUH_INDEXER_USER", "").strip()
    password = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
    verify_env = os.environ.get("WAZUH_INDEXER_VERIFY_TLS", "true").strip().lower()
    verify = verify_env not in ("0", "false", "no")

    missing = []
    if not url:
        missing.append("WAZUH_INDEXER_URL")
    if not user:
        missing.append("WAZUH_INDEXER_USER")
    if not password:
        missing.append("WAZUH_INDEXER_PASSWORD")
    if missing:
        raise RuntimeError(
            "Missing Wazuh indexer credentials in environment: "
            + ", ".join(missing)
            + " (set them in the environment; never hardcode credentials)."
        )
    return url, user, password, verify


def _request_with_retry(session, method: str, url: str, blog, **kwargs):
    """Issue an HTTP request with exponential backoff on transient failures."""
    import requests  # local import: indexer mode only

    kwargs.setdefault("timeout", INDEXER_TIMEOUT_SECONDS)
    last_exc: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = session.request(method, url, **kwargs)
            # Retry on 429 / 5xx; surface other 4xx immediately.
            if resp.status_code in (429,) or 500 <= resp.status_code < 600:
                raise requests.HTTPError(f"{resp.status_code} {resp.reason}", response=resp)
            resp.raise_for_status()
            return resp
        except (requests.ConnectionError, requests.Timeout, requests.HTTPError) as exc:
            last_exc = exc
            if attempt >= MAX_RETRIES:
                break
            sleep_for = BACKOFF_BASE_SECONDS ** attempt
            _emit(blog, "warning", "indexer.retry",
                  attempt=attempt, sleep=round(sleep_for, 2), error=str(exc))
            time.sleep(sleep_for)
    raise RuntimeError(f"Wazuh indexer request failed after {MAX_RETRIES} attempts: {last_exc}")


def read_indexer_documents(index_pattern: str, lookback: str, blog) -> Iterator[dict]:
    """Yield documents from the Wazuh indexer over a lookback window.

    Uses a Point-in-Time (PIT) + ``search_after`` cursor for stable, deep
    pagination. Falls back to a plain ``search_after`` sort if PIT is not
    available on the indexer build.
    """
    try:
        import requests  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment guard
        raise RuntimeError(
            "The 'requests' library is required for --mode indexer. Install it: pip install requests"
        ) from exc
    import requests

    url, user, password, verify = _indexer_credentials()
    lookback_seconds = parse_lookback_seconds(lookback)
    gte = f"now-{lookback_seconds}s"

    session = requests.Session()
    session.auth = (user, password)
    session.headers.update({"Content-Type": "application/json"})
    session.verify = verify
    if not verify:
        blog.warning("indexer.tls_verify_disabled")
        try:
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        except Exception:
            pass

    base_query = {
        "size": INDEXER_PAGE_SIZE,
        "query": {"range": {"timestamp": {"gte": gte}}},
        "sort": [{"timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}],
    }

    pit_id = _open_pit(session, url, index_pattern, blog)
    yielded = 0
    try:
        search_after = None
        while True:
            body = dict(base_query)
            if pit_id:
                body["pit"] = {"id": pit_id, "keep_alive": PIT_KEEP_ALIVE}
                search_url = f"{url}/_search"
            else:
                search_url = f"{url}/{index_pattern}/_search"
            if search_after is not None:
                body["search_after"] = search_after

            resp = _request_with_retry(session, "POST", search_url, blog, data=json.dumps(body))
            payload = resp.json()
            hits = (payload.get("hits") or {}).get("hits") or []
            if not hits:
                break
            for hit in hits:
                yield _unwrap_source(hit)
                yielded += 1
            search_after = hits[-1].get("sort")
            if search_after is None:
                break
            # PIT id can be refreshed across pages.
            pit_id = payload.get("pit_id", pit_id)
    finally:
        if pit_id:
            _close_pit(session, url, pit_id, blog)
        _emit(blog, "info", "indexer.read_done", documents=yielded)


def _open_pit(session, url: str, index_pattern: str, blog) -> str | None:
    """Open a Point-in-Time for stable pagination; return None if unsupported."""
    try:
        resp = session.post(
            f"{url}/{index_pattern}/_search/point_in_time",
            params={"keep_alive": PIT_KEEP_ALIVE},
            timeout=INDEXER_TIMEOUT_SECONDS,
        )
        if resp.status_code >= 400:
            _emit(blog, "warning", "indexer.pit_unavailable", status=resp.status_code)
            return None
        return resp.json().get("pit_id") or resp.json().get("id")
    except Exception as exc:  # pragma: no cover - network dependent
        _emit(blog, "warning", "indexer.pit_error", error=str(exc))
        return None


def _close_pit(session, url: str, pit_id: str, blog) -> None:
    """Best-effort PIT cleanup."""
    try:
        session.delete(
            f"{url}/_search/point_in_time",
            data=json.dumps({"pit_id": pit_id}),
            timeout=INDEXER_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # pragma: no cover - network dependent
        _emit(blog, "warning", "indexer.pit_close_error", error=str(exc))


# ─── Batching + classification ───────────────────────────────────

def group_documents(documents: Iterable[dict]) -> dict[str, list[dict]]:
    """Classify documents and group them by OCI LA source display name."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    for doc in documents:
        source = classify_document(doc)
        grouped[source].append(doc)
    return grouped


def _to_ndjson_bytes(docs: list[dict]) -> bytes:
    """Serialize documents back to NDJSON (one JSON object per line)."""
    buf = io.StringIO()
    for doc in docs:
        # Drop the synthetic _index marker so the uploaded JSON matches the
        # parser EXAMPLE shapes exactly.
        clean = {k: v for k, v in doc.items() if k != "_index"}
        buf.write(json.dumps(clean, separators=(",", ":")))
        buf.write("\n")
    return buf.getvalue().encode("utf-8")


def _batched(items: list[dict], size: int) -> Iterator[list[dict]]:
    """Yield successive batches of at most ``size`` items."""
    for start in range(0, len(items), max(1, size)):
        yield items[start:start + size]


# ─── OCI upload ──────────────────────────────────────────────────

def _upload_batch(la_client, namespace, log_group_id, source_name, upload_name,
                  body_bytes, filename, blog):
    """Upload one NDJSON batch via the Log Analytics Upload API (with retry)."""
    import oci

    last_exc: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = la_client.upload_log_file(
                namespace_name=namespace,
                upload_name=upload_name,
                log_source_name=source_name,
                filename=filename,
                opc_meta_loggrpid=log_group_id,
                upload_log_file_body=io.BytesIO(body_bytes),
                content_type="application/octet-stream",
                char_encoding="UTF-8",
            )
            req_id = response.headers.get("opc-request-id", "N/A")
            _emit(blog, "info", "upload.ok",
                  source=source_name, status=response.status, request_id=req_id)
            return True
        except oci.exceptions.ServiceError as exc:
            last_exc = exc
            # 4xx other than throttling are not retryable.
            if exc.status not in (429,) and not (500 <= exc.status < 600):
                _emit(blog, "error", "upload.service_error",
                      source=source_name, status=exc.status, message=exc.message)
                if "source" in str(exc.message).lower():
                    _emit(blog, "error", "upload.source_hint", source=source_name,
                          hint="create the source via scripts/setup_log_sources.py")
                return False
            if attempt >= MAX_RETRIES:
                break
            sleep_for = BACKOFF_BASE_SECONDS ** attempt
            _emit(blog, "warning", "upload.retry", source=source_name,
                  attempt=attempt, status=exc.status, sleep=round(sleep_for, 2))
            time.sleep(sleep_for)
    _emit(blog, "error", "upload.failed", source=source_name, error=str(last_exc))
    return False


# ─── Orchestration ───────────────────────────────────────────────

def collect_documents(args, blog) -> Iterator[dict]:
    """Return the document iterator for the selected mode."""
    if args.mode == "file":
        if not args.file:
            raise ValueError("--mode file requires --file <path>")
        _emit(blog, "info", "input.file", path=args.file)
        return read_file_documents(args.file)
    if args.mode == "stdin":
        blog.info("input.stdin")
        return read_stdin_documents()
    # indexer
    _emit(blog, "info", "input.indexer",
          index_pattern=args.index_pattern, lookback=args.lookback)
    return read_indexer_documents(args.index_pattern, args.lookback, blog)


def run(args, blog) -> int:
    """Execute the forward run. Returns a process exit code."""
    documents = list(collect_documents(args, blog))
    grouped = group_documents(documents)

    total = sum(len(v) for v in grouped.values())
    summary = {SOURCE_UPLOAD_SUFFIX[s]: len(grouped.get(s, [])) for s in ALL_SOURCES}
    _emit(blog, "info", "classify.summary", total=total, **summary)

    if total == 0:
        print("No Wazuh documents to forward (empty input / lookback window).")
        return 0

    if args.dry_run:
        _print_dry_run(grouped, args)
        return 0

    # Live path: resolve OCI client/namespace/log-group and enforce write guard.
    require_oci_config()
    try:
        assert_write_allowed(resolve_compartment_id(), override=args.i_understand_prod)
    except ProdWriteGuardError as guard_err:
        _emit(blog, "error", "prod_write_blocked", override=args.i_understand_prod)
        print(f"\n  {guard_err}")
        return 2

    print("Connecting to OCI Log Analytics...")
    la_client = get_la_client()
    namespace = get_namespace(la_client)
    log_group_id = ensure_log_group(la_client, namespace)
    available = list_available_log_sources(la_client, namespace, resolve_compartment_id())
    _emit(blog, "info", "oci.ready", namespace=namespace, available_sources=len(available))

    ok_sources = 0
    failed_sources = 0
    for source_name in ALL_SOURCES:
        docs = grouped.get(source_name)
        if not docs:
            continue
        resolved = resolve_source_from_candidates(available, SOURCE_CANDIDATES[source_name])
        if not resolved:
            resolved = source_name
            _emit(blog, "warning", "source.not_found", source=source_name,
                  hint="run scripts/setup_log_sources.py to create Wazuh sources")
        suffix = SOURCE_UPLOAD_SUFFIX[source_name]
        batch_ok = True
        for batch_no, batch in enumerate(_batched(docs, args.batch_size), start=1):
            body = _to_ndjson_bytes(batch)
            upload_name = f"wazuh-{suffix}-{RUN_TAG}-{batch_no}"
            filename = f"wazuh_{suffix}_{batch_no}.jsonl"
            print(f"  Uploading {len(batch)} -> '{resolved}' (batch {batch_no}, {len(body)} bytes)")
            if not _upload_batch(la_client, namespace, log_group_id, resolved,
                                 upload_name, body, filename, blog):
                batch_ok = False
        if batch_ok:
            ok_sources += 1
        else:
            failed_sources += 1

    print("\n" + "=" * 60)
    print(f"Wazuh -> OCI LA forward complete: {ok_sources} source(s) OK, "
          f"{failed_sources} with errors, {total} documents.")
    _emit(blog, "info", "forward.done", ok_sources=ok_sources,
          failed_sources=failed_sources, documents=total)
    return 0 if failed_sources == 0 else 1


def _print_dry_run(grouped: dict[str, list[dict]], args) -> None:
    """Print what would be uploaded without calling OCI."""
    print("\n" + "=" * 60)
    print("DRY-RUN — no OCI calls will be made")
    print("=" * 60)
    for source_name in ALL_SOURCES:
        docs = grouped.get(source_name, [])
        print(f"\n  {source_name}: {len(docs)} document(s)")
        if not docs:
            continue
        batches = list(_batched(docs, args.batch_size))
        print(f"    -> {len(batches)} batch(es) at batch-size {args.batch_size}")
        sample = docs[0]
        agent = (sample.get("agent") or {}).get("name", "?")
        rule = (sample.get("rule") or {}).get("description") \
            or (sample.get("vulnerability") or {}).get("cve") \
            or (sample.get("full_log") or "")
        preview = str(rule)[:80]
        print(f"    sample: agent={agent} :: {preview}")
    print("\n  (re-run without --dry-run to upload)")


# Stable per-process tag for upload names (PID-based; never time/random so
# deterministic-output hooks stay happy — mirrors obs_logging.RUN_ID).
RUN_TAG = os.environ.get("OCI_RUN_ID") or f"{os.getpid():x}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Forward live Wazuh telemetry into OCI Log Analytics.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode", choices=["indexer", "stdin", "file"], default="indexer",
        help="Input source: indexer (OpenSearch REST), stdin (NDJSON), or file (NDJSON).",
    )
    parser.add_argument(
        "--lookback", default=DEFAULT_LOOKBACK,
        help="Indexer lookback window, e.g. 15m, 2h, 1d (default: %(default)s).",
    )
    parser.add_argument(
        "--index-pattern", default=DEFAULT_INDEX_PATTERN,
        help="Indexer index pattern to query (default: %(default)s).",
    )
    parser.add_argument(
        "--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
        help="Documents per OCI upload batch (default: %(default)s).",
    )
    parser.add_argument(
        "--file", default=None,
        help="NDJSON file path (required for --mode file).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Classify and report what would be uploaded; do not call OCI.",
    )
    parser.add_argument(
        "--i-understand-prod", action="store_true", dest="i_understand_prod",
        help="Acknowledge a deliberate upload against the emdemo PRODUCTION tenancy "
             "outside the LogAnalytics subtree (or set OCI_ALLOW_PROD_WRITE=1).",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    blog = bind(log, mode=args.mode, dry_run=args.dry_run)
    blog.info("wazuh_forward.start")

    try:
        exit_code = run(args, blog)
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        _emit(blog, "error", "wazuh_forward.error", error=str(exc))
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
