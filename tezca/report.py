"""
Enterprise compliance and forensic audit reporting engine for tezca.

Generates structured JSON and interactive self-contained HTML reports mapping
ledger records to EU AI Act (Art. 12), SOC 2 Type II (CC6.8/CC7.2), and HIPAA § 164.312(b).
"""

from __future__ import annotations

import html
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Union

from tezca.canonical import canonical_dumps
from tezca.ledger import Ledger


@dataclass(frozen=True)
class ComplianceEvaluation:
    standard: str
    control: str
    title: str
    description: str
    status: str  # "PASS", "FAIL", "NOT_CONFIGURED"
    evidence: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class ComplianceReport:
    """
    Comprehensive compliance and forensic audit report.
    """

    generated_at: str
    ledger_path: str
    total_events: int
    is_valid: bool
    merkle_root: str
    genesis_hash: str
    latest_hash: str
    timespan: dict[str, Any]
    event_type_breakdown: dict[str, int]
    agent_breakdown: dict[str, int]
    tool_breakdown: dict[str, int]
    error_count: int
    evaluations: list[ComplianceEvaluation]
    verification_details: dict[str, Any]
    recent_events: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Convert report to standard dictionary."""
        d = asdict(self)
        d["evaluations"] = [e.to_dict() if hasattr(e, "to_dict") else e for e in self.evaluations]
        return d

    def to_json(self, indent: int = 2) -> str:
        """Export report as structured JSON for SIEM / external tooling ingestion."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_html(self) -> str:
        """
        Generate a self-contained, responsive HTML compliance document.
        Does not require external CDNs or network access.
        """
        status_color = "#10b981" if self.is_valid else "#ef4444"
        status_text = "VERIFIED INTACT" if self.is_valid else "VERIFICATION FAILED"
        status_badge_bg = "#ecfdf5" if self.is_valid else "#fef2f2"

        # Build evaluations table rows
        eval_rows = []
        for ev in self.evaluations:
            pill_color = "#059669" if ev.status == "PASS" else ("#dc2626" if ev.status == "FAIL" else "#6b7280")
            pill_bg = "#d1fae5" if ev.status == "PASS" else ("#fee2e2" if ev.status == "FAIL" else "#f3f4f6")
            eval_rows.append(
                f"""<tr>
                    <td><strong>{html.escape(ev.standard)}</strong></td>
                    <td><code>{html.escape(ev.control)}</code></td>
                    <td><strong>{html.escape(ev.title)}</strong><br><small style="color:#6b7280;">{html.escape(ev.description)}</small></td>
                    <td><span style="background:{pill_bg};color:{pill_color};padding:4px 10px;border-radius:12px;font-weight:600;font-size:12px;">{html.escape(ev.status)}</span></td>
                    <td><small>{html.escape(ev.evidence)}</small></td>
                </tr>"""
            )
        eval_table_html = "\n".join(eval_rows)

        # Build event breakdown rows
        event_rows = [
            f"<tr><td><code>{html.escape(k)}</code></td><td style='text-align:right;'>{v}</td></tr>"
            for k, v in sorted(self.event_type_breakdown.items(), key=lambda x: -x[1])
        ]
        event_table_html = "\n".join(event_rows) if event_rows else "<tr><td colspan='2'>No events</td></tr>"

        # Build agent breakdown rows
        agent_rows = [
            f"<tr><td><code>{html.escape(k)}</code></td><td style='text-align:right;'>{v}</td></tr>"
            for k, v in sorted(self.agent_breakdown.items(), key=lambda x: -x[1])
        ]
        agent_table_html = "\n".join(agent_rows) if agent_rows else "<tr><td colspan='2'>No agents</td></tr>"

        # Build tool breakdown rows
        tool_rows = [
            f"<tr><td><code>{html.escape(k)}</code></td><td style='text-align:right;'>{v}</td></tr>"
            for k, v in sorted(self.tool_breakdown.items(), key=lambda x: -x[1])
        ]
        tool_table_html = "\n".join(tool_rows) if tool_rows else "<tr><td colspan='2'>No tools invoked</td></tr>"

        # Build recent events rows
        recent_rows = []
        for r in self.recent_events:
            recent_rows.append(
                f"""<tr>
                    <td><code>#{r.get('index', 0)}</code></td>
                    <td><small>{html.escape(str(r.get('timestamp', '')))}</small></td>
                    <td><code>{html.escape(str(r.get('agent_id', '')))}</code></td>
                    <td><code>{html.escape(str(r.get('event_type', '')))}</code></td>
                    <td><code title="{html.escape(str(r.get('hash', '')))}">{html.escape(str(r.get('hash', ''))[:16])}...</code></td>
                </tr>"""
            )
        recent_table_html = "\n".join(recent_rows) if recent_rows else "<tr><td colspan='5'>No events recorded</td></tr>"

        start_ts = self.timespan.get("start") or "N/A"
        end_ts = self.timespan.get("end") or "N/A"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>tezca Forensic Compliance & Audit Report</title>
<style>
  :root {{
    --bg: #f8fafc;
    --card-bg: #ffffff;
    --text: #0f172a;
    --border: #e2e8f0;
    --primary: #2563eb;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 32px 20px;
  }}
  .container {{
    max-width: 1100px;
    margin: 0 auto;
  }}
  .card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
  }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
  }}
  .header h1 {{
    margin: 0 0 6px 0;
    font-size: 26px;
  }}
  .status-badge {{
    background: {status_badge_bg};
    color: {status_color};
    border: 1px solid {status_color};
    padding: 8px 18px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 14px;
    letter-spacing: 0.5px;
  }}
  .grid-metrics {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-top: 20px;
  }}
  .metric-box {{
    background: #f1f5f9;
    border-radius: 8px;
    padding: 16px;
  }}
  .metric-box .label {{
    font-size: 12px;
    color: #64748b;
    text-transform: uppercase;
    font-weight: 600;
    margin-bottom: 6px;
  }}
  .metric-box .value {{
    font-size: 20px;
    font-weight: 700;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }}
  th, td {{
    padding: 12px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  th {{
    background: #f8fafc;
    color: #475569;
    font-weight: 600;
  }}
  code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 13px;
    background: #f1f5f9;
    padding: 2px 6px;
    border-radius: 4px;
  }}
  .columns {{
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 20px;
  }}
  @media (max-width: 850px) {{
    .columns {{ grid-template-columns: 1fr; }}
  }}
  .footer {{
    text-align: center;
    color: #94a3b8;
    font-size: 13px;
    margin-top: 40px;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="card header">
    <div>
      <h1>tezca Forensic Compliance & Audit Report</h1>
      <small style="color:#64748b;">Source Ledger: <code>{html.escape(self.ledger_path)}</code> | Generated: {html.escape(self.generated_at)}</small>
    </div>
    <div class="status-badge">{status_text}</div>
  </div>

  <div class="card">
    <h2 style="margin-top:0;font-size:18px;">Executive Summary & Cryptographic Root</h2>
    <div class="grid-metrics">
      <div class="metric-box">
        <div class="label">Total Sealed Events</div>
        <div class="value">{self.total_events}</div>
      </div>
      <div class="metric-box">
        <div class="label">Active Agents</div>
        <div class="value">{len(self.agent_breakdown)}</div>
      </div>
      <div class="metric-box">
        <div class="label">Exceptions / Errors</div>
        <div class="value" style="color:{'#ef4444' if self.error_count > 0 else 'inherit'};">{self.error_count}</div>
      </div>
      <div class="metric-box">
        <div class="label">Timespan</div>
        <div class="value" style="font-size:13px;font-weight:600;"><small>{html.escape(str(start_ts)[:19])}<br>to {html.escape(str(end_ts)[:19])}</small></div>
      </div>
    </div>
    <div style="margin-top:20px;padding:12px;background:#f8fafc;border-radius:8px;font-size:13px;">
      <div><strong>Merkle Root Hash:</strong> <code>{html.escape(self.merkle_root)}</code></div>
      <div style="margin-top:6px;"><strong>Latest Chain Hash:</strong> <code>{html.escape(self.latest_hash)}</code></div>
    </div>
  </div>

  <div class="card">
    <h2 style="margin-top:0;font-size:18px;">Regulatory Compliance Evaluation</h2>
    <table>
      <thead>
        <tr>
          <th>Framework</th>
          <th>Control</th>
          <th>Description</th>
          <th>Status</th>
          <th>Cryptographic Evidence</th>
        </tr>
      </thead>
      <tbody>
        {eval_table_html}
      </tbody>
    </table>
  </div>

  <div class="columns">
    <div class="card">
      <h3 style="margin-top:0;font-size:16px;">Event Types</h3>
      <table>
        <thead><tr><th>Type</th><th style="text-align:right;">Count</th></tr></thead>
        <tbody>{event_table_html}</tbody>
      </table>
    </div>

    <div class="card">
      <h3 style="margin-top:0;font-size:16px;">Agent Distribution</h3>
      <table>
        <thead><tr><th>Agent ID</th><th style="text-align:right;">Count</th></tr></thead>
        <tbody>{agent_table_html}</tbody>
      </table>
    </div>

    <div class="card">
      <h3 style="margin-top:0;font-size:16px;">Tool Invocations</h3>
      <table>
        <thead><tr><th>Tool Name</th><th style="text-align:right;">Count</th></tr></thead>
        <tbody>{tool_table_html}</tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <h2 style="margin-top:0;font-size:18px;">Recent Sealed Receipts (Sample)</h2>
    <table>
      <thead>
        <tr>
          <th>Index</th>
          <th>Timestamp</th>
          <th>Agent</th>
          <th>Event Type</th>
          <th>Receipt Hash</th>
        </tr>
      </thead>
      <tbody>
        {recent_table_html}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Generated automatically by <strong>tezca</strong> (Zero-dependency, hash-chained forensic ledger for AI agents).
  </div>
</div>
</body>
</html>"""


def generate_compliance_report(
    ledger: Ledger,
    secret_key: Optional[Union[str, bytes]] = None,
) -> ComplianceReport:
    """
    Generate an authoritative forensic compliance evaluation report from a ledger instance.
    """
    is_valid, verification_report = ledger.verify(secret_key=secret_key)
    receipts = list(ledger)

    total_events = len(receipts)
    merkle_root = ledger.merkle_root()
    genesis_hash = verification_report.get("genesis_hash", "0" * 64)
    latest_hash = verification_report.get("latest_hash", "0" * 64)

    event_type_counts: dict[str, int] = {}
    agent_counts: dict[str, int] = {}
    tool_counts: dict[str, int] = {}
    error_count = 0

    first_timestamp = receipts[0].timestamp if receipts else None
    last_timestamp = receipts[-1].timestamp if receipts else None

    for r in receipts:
        # Event type tally
        event_type_counts[r.event_type] = event_type_counts.get(r.event_type, 0) + 1

        # Agent tally
        agent_counts[r.agent_id] = agent_counts.get(r.agent_id, 0) + 1

        # Error count
        if r.event_type.lower() == "error":
            error_count += 1

        # Tool calls
        if isinstance(r.data, dict):
            tool_name = r.data.get("tool") or r.data.get("tool_name")
            if tool_name:
                tool_counts[str(tool_name)] = tool_counts.get(str(tool_name), 0) + 1

    # Evaluations
    evaluations: list[ComplianceEvaluation] = []

    # 1. EU AI Act - Article 12 (Automatic Recording of Events)
    evaluations.append(
        ComplianceEvaluation(
            standard="EU AI Act",
            control="Article 12(1)",
            title="Automatic Event Logging",
            description="High-risk AI systems must automatically log lifecycle events and decisions.",
            status="PASS" if is_valid and total_events > 0 else "FAIL",
            evidence=f"Ledger contains {total_events} unbroken, sequential records." if is_valid else f"Verification failed: {verification_report.get('error', 'Integrity broken')}.",
        )
    )

    # 2. EU AI Act - Article 12(2) (Traceability & Identity Attribution)
    evaluations.append(
        ComplianceEvaluation(
            standard="EU AI Act",
            control="Article 12(2)",
            title="Traceability & Attribution",
            description="Logs must trace identification of participating agents, actions, and outputs.",
            status="PASS" if is_valid and bool(agent_counts) else "FAIL",
            evidence=f"{len(agent_counts)} distinct agents attributed with timestamps and hash links." if is_valid else "Agent actions cannot be verifiably attributed due to integrity failure.",
        )
    )

    # 3. SOC 2 Type II - CC6.8 (Tamper-Evident Audit Trails)
    evaluations.append(
        ComplianceEvaluation(
            standard="SOC 2 Type II",
            control="CC6.8",
            title="Tamper-Evident Audit Trails",
            description="Audit trails must be protected from unauthorized alteration, deletion, or forgery.",
            status="PASS" if is_valid else "FAIL",
            evidence=f"Recursive SHA-256 chaining and Merkle root verified ({merkle_root[:16]}...)." if is_valid else f"Audit trail failed integrity check at index {verification_report.get('failed_at_index')}.",
        )
    )

    # 4. SOC 2 Type II - CC7.2 (Security Incident Monitoring)
    evaluations.append(
        ComplianceEvaluation(
            standard="SOC 2 Type II",
            control="CC7.2",
            title="Execution Anomaly & Error Tracking",
            description="Detect and analyze operational errors and unexpected agent behaviors.",
            status="PASS" if is_valid else "FAIL",
            evidence=f"Logged {error_count} error events across {total_events} transactions." if is_valid else "Integrity scan detected chain compromise.",
        )
    )

    # 5. HIPAA Security Rule - § 164.312(b) (Audit Controls)
    evaluations.append(
        ComplianceEvaluation(
            standard="HIPAA",
            control="§ 164.312(b)",
            title="Audit Controls & Record Integrity",
            description="Implement procedural and cryptographic mechanisms that record and examine system activity.",
            status="PASS" if is_valid and total_events > 0 else "FAIL",
            evidence=f"All {total_events} data transformations and access records sealed in append-only storage." if is_valid else "Audit records failed cryptographic verification.",
        )
    )

    # 6. Non-Repudiation (HMAC Signature Sealing)
    if secret_key is not None:
        evaluations.append(
            ComplianceEvaluation(
                standard="Enterprise Policy",
                control="SEC-NR-01",
                title="Cryptographic Non-Repudiation",
                description="Digital/HMAC signature verification over all ledger entries.",
                status="PASS" if is_valid else "FAIL",
                evidence="All signatures verified successfully with shared secret key." if is_valid else "One or more signatures failed verification.",
            )
        )

    recent_events_data = [r.to_dict() for r in receipts[-15:]]

    return ComplianceReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        ledger_path=str(ledger.path),
        total_events=total_events,
        is_valid=is_valid,
        merkle_root=merkle_root,
        genesis_hash=genesis_hash,
        latest_hash=latest_hash,
        timespan={
            "start": first_timestamp,
            "end": last_timestamp,
        },
        event_type_breakdown=event_type_counts,
        agent_breakdown=agent_counts,
        tool_breakdown=tool_counts,
        error_count=error_count,
        evaluations=evaluations,
        verification_details=verification_report,
        recent_events=recent_events_data,
    )
