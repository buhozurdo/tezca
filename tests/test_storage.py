"""
Tests for storage backends and abstract base classes.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from tezca.receipt import Receipt
from tezca.storage import JSONLStorage, SQLiteStorage, StorageBackend


class DummyStorage(StorageBackend):
    pass


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_abstract_storage_backend_raises(self):
        s = DummyStorage()
        dummy_receipt = Receipt(0, "ts", "agent", "ev", {}, {}, "0"*64, "1"*64)

        with self.assertRaises(NotImplementedError):
            s.append(dummy_receipt)
        with self.assertRaises(NotImplementedError):
            s.get_latest()
        with self.assertRaises(NotImplementedError):
            s.get_by_index(0)
        with self.assertRaises(NotImplementedError):
            list(s.iter_all())
        with self.assertRaises(NotImplementedError):
            s.count()
        s.close()

    def test_jsonl_storage_methods(self):
        jsonl_path = Path(self.temp_dir.name) / "test.jsonl"
        storage = JSONLStorage(jsonl_path)

        self.assertIsNone(storage.get_latest())
        self.assertEqual(storage.count(), 0)
        self.assertIsNone(storage.get_by_index(0))

        r0 = Receipt(0, "2026-01-01T00:00:00Z", "agent", "start", {"v": 1}, {}, "0"*64, "a"*64)
        r1 = Receipt(1, "2026-01-01T00:00:01Z", "agent", "stop", {"v": 2}, {}, "a"*64, "b"*64)
        storage.append(r0)
        storage.append(r1)

        self.assertEqual(storage.count(), 2)
        latest = storage.get_latest()
        self.assertIsNotNone(latest)
        self.assertEqual(latest.index, 1)

        found_r0 = storage.get_by_index(0)
        self.assertIsNotNone(found_r0)
        self.assertEqual(found_r0.index, 0)

        self.assertIsNone(storage.get_by_index(999))

        # Test iter_all on non-existent file
        jsonl_path.unlink()
        storage_missing = JSONLStorage(jsonl_path)
        jsonl_path.unlink()
        self.assertEqual(list(storage_missing.iter_all()), [])

    def test_sqlite_migration_existing_table(self):
        db_path = Path(self.temp_dir.name) / "legacy.db"

        # Simulate legacy v0.1.0 database without signature and signer_id columns
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE tezca_receipts (
                index_num INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL UNIQUE
            );
        """)
        cur.execute("""
            INSERT INTO tezca_receipts VALUES (
                0, '2026-11-19T00:00:00Z', 'legacy-agent', 'legacy-type',
                '{"k":"v"}', '{}', '0000000000000000000000000000000000000000000000000000000000000000', '1111111111111111111111111111111111111111111111111111111111111111'
            );
        """)
        conn.commit()
        conn.close()

        # Opening with SQLiteStorage should auto-migrate without errors
        storage = SQLiteStorage(db_path)
        self.assertEqual(storage.count(), 1)
        r = storage.get_by_index(0)
        self.assertIsNotNone(r)
        self.assertIsNone(r.signature)
        self.assertIsNone(r.signer_id)
        storage.close()


if __name__ == "__main__":
    unittest.main()
