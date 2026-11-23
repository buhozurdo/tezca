"""
Demonstration of enterprise compliance and forensic audit reporting (EU AI Act, SOC2, HIPAA).
"""

import sys
from pathlib import Path

# Allow direct execution from repository root without prior pip install
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from tezca import (
    AgentEvent,
    AgentEventType,
    Ledger,
    generate_compliance_report,
)


def run_compliance_demo():
    db_file = Path("compliance_audit.db")
    if db_file.exists():
        db_file.unlink()

    signing_key = "corp-hsm-signing-key-99"

    print("1. Initializing ledger and recording enterprise agent workflow...")
    with Ledger(db_file, secret_key=signing_key, signer_id="finance-agent-01") as ledger:
        # Prompt event
        ledger.record_event(
            AgentEvent(
                agent_id="finance-agent-01",
                event_type=AgentEventType.PROMPT,
                data={"prompt": "Process quarterly expense reconciliation for vendor #8412"},
                session_id="audit_sess_9001",
            )
        )

        # Tool execution event
        ledger.record_event(
            AgentEvent(
                agent_id="finance-agent-01",
                event_type=AgentEventType.TOOL_CALL,
                data={
                    "tool": "verify_bank_account",
                    "routing_number": "121000358",
                    "account_last4": "8841",
                },
                session_id="audit_sess_9001",
            )
        )

        # Tool result event
        ledger.record_event(
            AgentEvent(
                agent_id="finance-agent-01",
                event_type=AgentEventType.TOOL_RESULT,
                data={"tool": "verify_bank_account", "status": "VERIFIED_ACTIVE"},
                session_id="audit_sess_9001",
            )
        )

        # Guardrail verdict
        ledger.record_event(
            AgentEvent(
                agent_id="compliance-guardrail",
                event_type=AgentEventType.GUARDRAIL_VERDICT,
                data={"rule": "anti_money_laundering_threshold", "verdict": "PASSED"},
                session_id="audit_sess_9001",
            )
        )

        # Completion event
        ledger.record_event(
            AgentEvent(
                agent_id="finance-agent-01",
                event_type=AgentEventType.COMPLETION,
                data={"action": "SCHEDULE_PAYMENT", "amount_usd": 18450.00},
                session_id="audit_sess_9001",
            )
        )

        print("2. Generating formal compliance report...")
        report = generate_compliance_report(ledger, secret_key=signing_key)

        print(f"\n[OK] Report generated: {report.total_events} events evaluated.")
        print(f"[OK] Chain integrity: {'VALID' if report.is_valid else 'COMPROMISED'}")
        print(f"[OK] Merkle root: {report.merkle_root}")
        print("\nCompliance Matrix:")
        for ev in report.evaluations:
            print(f"  - [{ev.status}] {ev.standard} {ev.control}: {ev.title}")

        # Export HTML report
        html_file = Path("compliance_report.html")
        html_file.write_text(report.to_html(), encoding="utf-8")
        print(f"\n[OK] Exported standalone HTML audit report: {html_file.resolve()}")

        # Export JSON report for SIEM ingestion (Splunk, Elastic, Datadog)
        json_file = Path("compliance_report.json")
        json_file.write_text(report.to_json(indent=2), encoding="utf-8")
        print(f"[OK] Exported structured JSON SIEM report: {json_file.resolve()}")

    # Clean up generated files
    for p in [db_file, Path("compliance_report.html"), Path("compliance_report.json")]:
        if p.exists():
            p.unlink()
    print("\n[OK] Demo completed successfully.")


if __name__ == "__main__":
    run_compliance_demo()
