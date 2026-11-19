"""
Tests for Ledger recording, sequence chaining, and verification.
"""

import tempfile
import unittest
from pathlib import Path

from tezca.canonical import GENESIS_HASH
from tezca.ledger import Ledger


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_audit.db"
        self.jsonl_path = Path(self.temp_dir.name) / "test_audit.jsonl"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_record_and_chain_sqlite(self):
        with Ledger(self.db_path) as ledger:
            r0 = ledger.record(
                agent_id="agent-1",
                event_type="prompt",
                data={"input": "What is the weather?"},
            )
            self.assertEqual(r0.index, 0)
            self.assertEqual(r0.prev_hash, GENESIS_HASH)
            self.assertTrue(r0.verify_hash())

            r1 = ledger.record(
                agent_id="agent-1",
                event_type="tool_call",
                data={"tool": "get_weather", "city": "London"},
            )
            self.assertEqual(r1.index, 1)
            self.assertEqual(r1.prev_hash, r0.hash)
            self.assertTrue(r1.verify_hash())

            r2 = ledger.record(
                agent_id="agent-1",
                event_type="output",
                data={"response": "Rainy, 12C"},
            )
            self.assertEqual(r2.index, 2)
            self.assertEqual(r2.prev_hash, r1.hash)
            self.assertTrue(r2.verify_hash())

            self.assertEqual(len(ledger), 3)

            valid, report = ledger.verify()
            self.assertTrue(valid)
            self.assertEqual(report["verified_events"], 3)
            self.assertEqual(report["latest_hash"], r2.hash)

    def test_record_and_chain_jsonl(self):
        with Ledger(self.jsonl_path) as ledger:
            r0 = ledger.record(
                agent_id="agent-jsonl",
                event_type="start",
                data={"run_id": "123"},
            )
            r1 = ledger.record(
                agent_id="agent-jsonl",
                event_type="finish",
                data={"status": "completed"},
            )
            self.assertEqual(r1.prev_hash, r0.hash)
            valid, report = ledger.verify()
            self.assertTrue(valid)
            self.assertEqual(report["verified_events"], 2)

    def test_tail(self):
        with Ledger(self.db_path) as ledger:
            for i in range(5):
                ledger.record("agent", "step", {"step": i})

            tail_3 = ledger.tail(3)
            self.assertEqual(len(tail_3), 3)
            self.assertEqual([r.index for r in tail_3], [2, 3, 4])


if __name__ == "__main__":
    unittest.main()
