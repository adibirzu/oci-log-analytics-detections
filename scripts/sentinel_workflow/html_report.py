"""Static HTML report rendering for Sentinel conversion results."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from sentinel_workflow.reporting import (
    DEFAULT_DASHBOARD_INVENTORY,
    DEFAULT_HTML_PATH,
    DEFAULT_REPORT_PATH,
    DEFAULT_SENTINEL_DIR,
    _live_failures,
    _safe_error_summary,
    _top_items,
    load_promoted_query_counts,
    load_report,
    load_sentinel_dashboard_counts,
)


def _html_table(headers: Iterable[str], rows: Iterable[Iterable[object]], empty: str) -> str:
    headers = list(headers)
    rows = list(rows)
    header_html = "".join(f"<th>{html.escape(str(header))}</th>" for header in headers)
    if not rows:
        column_count = len(headers)
        return (
            "<table>"
            f"<thead><tr>{header_html}</tr></thead>"
            f"<tbody><tr><td colspan=\"{column_count}\">{html.escape(empty)}</td></tr></tbody>"
            "</table>"
        )
    body = []
    for row in rows:
        body.append("<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>")
    return f"<table><thead><tr>{header_html}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def render_report_html(
    report: dict,
    *,
    sentinel_counts: dict | None = None,
    dashboard_counts: dict[str, int] | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Render a static HTML review page for the Sentinel conversion report."""
    sentinel_counts = sentinel_counts or {}
    dashboard_counts = dashboard_counts or {}
    generated_at = generated_at or datetime.now(timezone.utc)
    summary = report.get("summary", {})
    source = report.get("source", {})
    unsupported = report.get("unsupported_features", {})
    categories = sentinel_counts.get("categories", {})
    levels = sentinel_counts.get("levels", {})
    live_status = sentinel_counts.get("live_status", {})

    metrics = [
        ("Candidates", summary.get("total_candidates", 0)),
        ("Attempted", summary.get("attempted_candidates", 0)),
        ("Promoted", summary.get("promoted_count", 0)),
        ("Live passed", summary.get("live_validation_passed", 0)),
        ("Live failed", summary.get("live_validation_failed", 0)),
        ("Promoted files", sentinel_counts.get("files", 0)),
    ]
    metric_html = "".join(
        "<section class=\"metric\">"
        f"<span>{html.escape(label)}</span>"
        f"<strong>{html.escape(str(value))}</strong>"
        "</section>"
        for label, value in metrics
    )

    category_rows = _top_items(categories)
    max_category = max((count for _name, count in category_rows), default=1)
    category_html = "".join(
        "<div class=\"bar-row\">"
        f"<span>{html.escape(name)}</span>"
        "<div class=\"bar-track\">"
        f"<div class=\"bar\" style=\"width: {int((count / max_category) * 100)}%\"></div>"
        "</div>"
        f"<strong>{count}</strong>"
        "</div>"
        for name, count in category_rows
    ) or "<p class=\"muted\">No promoted Sentinel queries found.</p>"

    dashboard_table = _html_table(
        ["Dashboard", "Widgets"],
        dashboard_counts.items(),
        "Dashboard inventory has not been generated.",
    )
    unsupported_table = _html_table(
        ["Reason", "Count"],
        _top_items(unsupported, limit=16),
        "No unsupported features recorded.",
    )
    failures_table = _html_table(
        ["Title", "Source path", "Error"],
        (
            (
                failure.get("title", ""),
                failure.get("source_path", ""),
                _safe_error_summary(failure.get("live_validation_error", "")),
            )
            for failure in _live_failures(report)
        ),
        "No live validation failures in the report.",
    )
    levels_table = _html_table(["Severity", "Promoted"], _top_items(levels), "No promoted severities.")
    live_table = _html_table(["Live status", "Promoted files"], _top_items(live_status), "No promoted live status.")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sentinel to Logan QL Conversion</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #17202a;
      --muted: #5f6b7a;
      --line: #d9e0e8;
      --panel: #f7f9fb;
      --accent: #0f766e;
      --accent-2: #b45309;
      --accent-3: #1d4ed8;
      --white: #ffffff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      background: var(--white);
      font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    header {{
      padding: 32px clamp(20px, 5vw, 64px) 24px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(90deg, #f8fafc, #f1f8f6 45%, #fff7ed);
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: clamp(28px, 4vw, 44px);
      line-height: 1.1;
      letter-spacing: 0;
    }}
    h2 {{
      margin: 0 0 14px;
      font-size: 20px;
      letter-spacing: 0;
    }}
    main {{
      padding: 28px clamp(20px, 5vw, 64px) 48px;
    }}
    .lede {{
      max-width: 980px;
      margin: 0;
      color: var(--muted);
      font-size: 16px;
    }}
    .meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px 24px;
      margin-top: 18px;
      color: var(--muted);
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
      gap: 12px;
      margin: 0 0 28px;
    }}
    .metric {{
      min-height: 96px;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
    }}
    .metric span {{
      display: block;
      color: var(--muted);
      font-size: 13px;
    }}
    .metric strong {{
      display: block;
      margin-top: 8px;
      font-size: 30px;
      line-height: 1;
    }}
    .grid {{
      display: grid;
      grid-template-columns: minmax(0, 1.15fr) minmax(280px, 0.85fr);
      gap: 18px;
      align-items: start;
    }}
    section.panel {{
      margin-bottom: 18px;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--white);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th, td {{
      padding: 10px 9px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-weight: 650;
      background: #f8fafc;
    }}
    .bar-row {{
      display: grid;
      grid-template-columns: minmax(105px, 170px) 1fr 48px;
      gap: 12px;
      align-items: center;
      margin: 10px 0;
    }}
    .bar-track {{
      height: 14px;
      border-radius: 999px;
      background: #edf2f7;
      overflow: hidden;
    }}
    .bar {{
      height: 100%;
      border-radius: 999px;
      background: linear-gradient(90deg, var(--accent), var(--accent-3));
    }}
    code {{
      padding: 2px 5px;
      border-radius: 5px;
      background: #eef2ff;
      color: #1e3a8a;
    }}
    pre {{
      overflow-x: auto;
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #111827;
      color: #f9fafb;
    }}
    .muted {{ color: var(--muted); }}
    .callout {{
      border-left: 4px solid var(--accent-2);
      padding-left: 14px;
      color: var(--muted);
    }}
    @media (max-width: 820px) {{
      .grid {{ grid-template-columns: 1fr; }}
      .bar-row {{ grid-template-columns: 1fr; gap: 6px; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Sentinel to Logan QL Conversion</h1>
    <p class="lede">Static review page for the Microsoft Sentinel conversion pipeline. Promoted queries are source-attributed, mapped to real OCI Log Analytics fields, and written only after live parser validation.</p>
    <div class="meta">
      <span>Generated: {html.escape(generated_at.isoformat())}</span>
      <span>Source: {html.escape(str(source.get("repository", "Microsoft Sentinel")))}</span>
      <span>Ranking: {html.escape(str(summary.get("ranking", "quality-first")))}</span>
    </div>
  </header>
  <main>
    <div class="metrics">{metric_html}</div>
    <div class="grid">
      <div>
        <section class="panel">
          <h2>Promoted Categories</h2>
          {category_html}
        </section>
        <section class="panel">
          <h2>Sentinel Dashboards</h2>
          {dashboard_table}
        </section>
        <section class="panel">
          <h2>Top Skip Reasons</h2>
          {unsupported_table}
        </section>
        <section class="panel">
          <h2>Live Validation Failures Kept Out</h2>
          {failures_table}
        </section>
      </div>
      <aside>
        <section class="panel">
          <h2>Severity Mix</h2>
          {levels_table}
        </section>
        <section class="panel">
          <h2>Promoted Live Status</h2>
          {live_table}
        </section>
        <section class="panel">
          <h2>Operator Commands</h2>
          <pre>python3 scripts/sentinel_conversion_workflow.py local
python3 scripts/sentinel_conversion_workflow.py promote --top all --timeout 20
python3 scripts/sentinel_conversion_workflow.py promote --top all --timeout 60 --progress-interval 0
python3 scripts/sentinel_conversion_workflow.py refresh-artifacts
python3 scripts/sentinel_conversion_workflow.py triage
python3 scripts/sentinel_conversion_workflow.py next-queries --limit 10
python3 scripts/sentinel_conversion_workflow.py next-queries --strategy foundational --limit 10
python3 scripts/sentinel_conversion_workflow.py status --json --strict</pre>
          <p class="callout">The local command writes to <code>/tmp/sentinel_conversion_local.json</code> by default so it does not overwrite the canonical live validation report.</p>
        </section>
      </aside>
    </div>
  </main>
</body>
</html>
"""


def write_report_html(
    *,
    report_path: Path = DEFAULT_REPORT_PATH,
    output_path: Path = DEFAULT_HTML_PATH,
    sentinel_dir: Path = DEFAULT_SENTINEL_DIR,
    dashboard_inventory: Path = DEFAULT_DASHBOARD_INVENTORY,
) -> Path:
    """Write the static HTML report page and return its path."""
    report = load_report(report_path)
    html_text = render_report_html(
        report,
        sentinel_counts=load_promoted_query_counts(sentinel_dir),
        dashboard_counts=load_sentinel_dashboard_counts(dashboard_inventory),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_text, encoding="utf-8")
    return output_path
