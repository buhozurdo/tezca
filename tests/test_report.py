"""
Tests for enterprise compliance and forensic audit reporting (tezca.report).
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from tezca.events import AgentEvent, AgentEventType
from tezca.ledger import Ledger
from tezca.report import ComplianceEvaluation, ComplianceReport, generate_compliance_report


class TestReport(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_report.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_compliance_evaluation_to_dict(self):
        ev = ComplianceEvaluation(
            standard="EU AI Act",
            control="Art 12",
            title="Auto Logging",
            description="Log events",
            status="PASS",
            evidence="Evidence details",
        )
        d = ev.to_dict()
        self.assertEqual(d["standard"], "EU AI Act")
        self.assertEqual(d["status"], "PASS")

    def test_generate_report_empty_ledger(self):
        with Ledger(self.db_path) as ledger:
            report = generate_compliance_report(ledger)

        self.assertEqual(report.total_events, 0)
        self.assertTrue(report.is_valid)
        self.assertEqual(report.error_count, 0)
        self.assertIsNone(report.timespan["start"])
        self.assertIsNone(report.timespan["end"])

        # Check export formats
        d = report.to_dict()
        self.assertEqual(d["total_events"], 0)

        json_str = report.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["total_events"], 0)

        html_str = report.to_html()
        self.assertIn("tezca Forensic Compliance & Audit Report", html_str)
        self.assertIn("VERIFIED INTACT", html_str)
        self.assertIn("No events", html_str)

    def test_generate_report_populated_ledger_with_hmac(self):
        secret = "corp-audit-secret-key"
        with Ledger(self.db_path, secret_key=secret, signer_id="sec-agent") as ledger:
            # 1. Prompt
            ledger.record(
                agent_id="support-bot",
                event_type=AgentEventType.PROMPT.value,
                data={"messages": ["Hello"]},
            )
            # 2. Tool call
            ledger.record(
                agent_id="support-bot",
                event_type=AgentEventType.TOOL_CALL.value,
                data={"tool": "search_db", "arguments": {"query": "customer_42"}},
            )
            # 3. Tool result
            ledger.record(
                agent_id="support-bot",
                event_type=AgentEventType.TOOL_RESULT.value,
                data={"tool_name": "search_db", "result": {"tier": "gold"}},
            )
            # 4. Completion
            ledger.record(
                agent_id="support-bot",
                event_type=AgentEventType.COMPLETION.value,
                data={"response": "User is a gold tier customer."},
            )
            # 5. Error
            ledger.record(
                agent_id="billing-bot",
                event_type=AgentEventType.ERROR.value,
                data={"error": "Card declined"},
            )
            # 6. Guardrail verdict via record_event
            ledger.record_event(
                AgentEvent(
                    agent_id="guard-bot",
                    event_type=AgentEventType.GUARDRAIL_VERDICT,
                    data={"rule": "pii_check", "status": "APPROVED"},
                )
            )

            report = generate_compliance_report(ledger, secret_key=secret)

        self.assertEqual(report.total_events, 6)
        self.assertTrue(report.is_valid)
        self.assertEqual(report.error_count, 1)
        self.assertEqual(report.tool_breakdown["search_db"], 2)
        self.assertEqual(report.agent_breakdown["support-bot"], 4)
        self.assertEqual(report.agent_breakdown["billing-bot"], 1)
        self.assertEqual(report.agent_breakdown["guard-bot"], 1)

        # Evaluations
        standards = {e.standard: e.status for e in report.evaluations}
        self.assertEqual(standards["EU AI Act"], "PASS")
        self.assertEqual(standards["SOC 2 Type II"], "PASS")
        self.assertEqual(standards["HIPAA"], "PASS")
        self.assertEqual(standards["Enterprise Policy"], "PASS")

        # HTML Rendering
        html_doc = report.to_html()
        self.assertIn("support-bot", html_doc)
        self.assertIn("search_db", html_doc)
        self.assertIn("EU AI Act", html_doc)
        self.assertIn("SOC 2 Type II", html_doc)
        self.assertIn("HIPAA", html_doc)
        self.assertIn("VERIFIED INTACT", html_doc)

    def test_generate_report_tampered_ledger(self):
        with Ledger(self.db_path) as ledger:
            for i in range(5):
                ledger.record("agent-x", "step", {"i": i})

        # Out of band tamper
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE tezca_receipts SET data_json = '{\"tampered\": true}' WHERE index_num = 2;")
        conn.commit()
        conn.close()

        with Ledger(self.db_path) as ledger:
            report = generate_compliance_report(ledger)

        self.assertFalse(report.is_valid)
        self.assertEqual(report.verification_details["failed_at_index"], 2)

        # Evaluations should show FAIL
        for ev in report.evaluations:
            self.assertEqual(ev.status, "FAIL")

        html_doc = report.to_html()
        self.assertIn("VERIFICATION FAILED", html_doc)


if __name__ == "__main__":
    unittest.main()
