"""
Tests verifying that any tampering breaks the cryptographic hash chain.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from tezca.ledger import Ledger


class TestTamperingDetection(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "tamper_test.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_detect_data_modification(self):
        # 1. Create a legitimate 3-event chain
        with Ledger(self.db_path) as ledger:
            ledger.record("agent", "action", {"amount": 100})
            ledger.record("agent", "action", {"amount": 200})
            ledger.record("agent", "action", {"amount": 300})

        # 2. Directly tamper with the database (simulate an attacker modifying record #1)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE tezca_receipts
            SET data_json = '{"amount":99999}'
            WHERE index_num = 1;
            """
        )
        conn.commit()
        conn.close()

        # 3. Verify must detect the tampering at index 1
        with Ledger(self.db_path) as ledger:
            valid, report = ledger.verify()
            self.assertFalse(valid)
            self.assertEqual(report["failed_at_index"], 1)
            self.assertIn("Hash integrity failed", report["error"])

    def test_detect_deleted_record(self):
        with Ledger(self.db_path) as ledger:
            ledger.record("agent", "step", {"step": 0})
            ledger.record("agent", "step", {"step": 1})
            ledger.record("agent", "step", {"step": 2})

        # Delete record #1
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("DELETE FROM tezca_receipts WHERE index_num = 1;")
        conn.commit()
        conn.close()

        with Ledger(self.db_path) as ledger:
            valid, report = ledger.verify()
            self.assertFalse(valid)
            self.assertEqual(report["failed_at_index"], 2)


if __name__ == "__main__":
    unittest.main()
