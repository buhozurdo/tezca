"""
Tests for standardized AgentEvent schema and typed enumerations.
"""

import tempfile
import unittest
from pathlib import Path

from tezca.events import AgentEvent, AgentEventType
from tezca.ledger import Ledger


class TestEvents(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "events_test.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_agent_event_types(self):
        self.assertEqual(AgentEventType.PROMPT.value, "prompt")
        self.assertEqual(AgentEventType.COMPLETION.value, "completion")
        self.assertEqual(AgentEventType.TOOL_CALL.value, "tool_call")
        self.assertEqual(AgentEventType.TOOL_RESULT.value, "tool_result")
        self.assertEqual(AgentEventType.GUARDRAIL_VERDICT.value, "guardrail_verdict")
        self.assertEqual(AgentEventType.AGENT_THOUGHT.value, "thought")
        self.assertEqual(AgentEventType.DELEGATION.value, "delegation")
        self.assertEqual(AgentEventType.ERROR.value, "error")
        self.assertEqual(AgentEventType.CUSTOM.value, "custom")

    def test_event_to_record_kwargs(self):
        ev = AgentEvent(
            agent_id="test-agent",
            event_type=AgentEventType.TOOL_CALL,
            data={"action": "calculate"},
            session_id="sess_123",
            model="gpt-4o",
            token_usage={"prompt": 10, "completion": 20},
            latency_ms=145.2,
            metadata={"environment": "production"},
        )
        kwargs = ev.to_record_kwargs()
        self.assertEqual(kwargs["agent_id"], "test-agent")
        self.assertEqual(kwargs["event_type"], "tool_call")
        self.assertEqual(kwargs["data"], {"action": "calculate"})
        self.assertEqual(kwargs["metadata"]["session_id"], "sess_123")
        self.assertEqual(kwargs["metadata"]["model"], "gpt-4o")
        self.assertEqual(kwargs["metadata"]["token_usage"], {"prompt": 10, "completion": 20})
        self.assertEqual(kwargs["metadata"]["latency_ms"], 145.2)
        self.assertEqual(kwargs["metadata"]["environment"], "production")

    def test_record_event_in_ledger(self):
        with Ledger(self.db_path) as ledger:
            ev = AgentEvent(
                agent_id="finance-agent",
                event_type=AgentEventType.GUARDRAIL_VERDICT,
                data={"check": "aml_kyc", "verdict": "PASS"},
            )
            r = ledger.record_event(ev)
            self.assertEqual(r.index, 0)
            self.assertEqual(r.event_type, "guardrail_verdict")
            self.assertTrue(r.verify_hash())

            valid, report = ledger.verify()
            self.assertTrue(valid)
            self.assertEqual(report["verified_events"], 1)


if __name__ == "__main__":
    unittest.main()
