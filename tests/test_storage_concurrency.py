"""
Concurrency, deadlock prevention, and WAL checkpoint tests for SQLiteStorage and Ledger.
"""

from __future__ import annotations

import concurrent.futures
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from tezca.ledger import Ledger
from tezca.receipt import Receipt
from tezca.storage import SQLiteStorage


class TestStorageConcurrency(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "concurrent_audit.db"

    def tearDown(self):
        # Explicit cleanup avoiding Windows file handle lock
        try:
            self.temp_dir.cleanup()
        except OSError:
            pass

    def test_multi_threaded_concurrent_appends(self):
        """Verify concurrent workers appending simultaneously do not crash or corrupt database."""
        num_workers = 6
        events_per_worker = 10

        def worker_task(worker_id: int):
            storage = SQLiteStorage(self.db_path, timeout=30.0)
            try:
                for i in range(events_per_worker):
                    r = Receipt(
                        index=worker_id * 1000 + i,
                        timestamp="2026-11-26T12:00:00Z",
                        agent_id=f"worker-{worker_id}",
                        event_type="action",
                        data={"worker": worker_id, "step": i},
                        metadata={},
                        prev_hash="0" * 64,
                        hash=f"{worker_id:04x}_{i:04x}" + "0" * 54,
                    )
                    storage.append(r)
            finally:
                storage.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(worker_task, w) for w in range(num_workers)]
            for f in concurrent.futures.as_completed(futures):
                f.result()

        with Ledger(self.db_path) as ledger:
            self.assertEqual(len(ledger), num_workers * events_per_worker)

    def test_wal_checkpoint_modes(self):
        """Verify WAL checkpoint execution across PASSIVE, FULL, RESTART, and TRUNCATE."""
        with Ledger(self.db_path) as ledger:
            for i in range(5):
                ledger.record("agent", "init", {"i": i})

            res_passive = ledger.checkpoint("PASSIVE")
            self.assertEqual(len(res_passive), 3)

            res_full = ledger.checkpoint("FULL")
            self.assertEqual(len(res_full), 3)

            res_restart = ledger.checkpoint("RESTART")
            self.assertEqual(len(res_restart), 3)

            res_truncate = ledger.checkpoint("TRUNCATE")
            self.assertEqual(len(res_truncate), 3)

            with self.assertRaises(ValueError):
                ledger.checkpoint("INVALID_MODE")

        jsonl_path = Path(self.temp_dir.name) / "test.jsonl"
        with Ledger(jsonl_path) as jsonl_ledger:
            self.assertEqual(jsonl_ledger.checkpoint(), (0, 0, 0))

    def test_retry_on_database_locked(self):
        """Verify automated exponential backoff retry when SQLite reports database locked."""
        storage = SQLiteStorage(self.db_path, timeout=0.05, max_retries=5, retry_delay=0.02)
        r = Receipt(
            index=0,
            timestamp="2026-11-26T12:00:00Z",
            agent_id="test-agent",
            event_type="test",
            data={"val": 1},
            metadata={},
            prev_hash="0" * 64,
            hash="h" * 64,
        )

        c2 = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
        try:
            c2.execute("BEGIN EXCLUSIVE;")
            # Schedule release of lock after 40ms so retry loop succeeds
            t = threading.Timer(0.04, lambda: c2.execute("COMMIT;"))
            t.start()
            storage.append(r)
            t.join()

            latest = storage.get_latest()
            self.assertIsNotNone(latest)
            self.assertEqual(latest.index, 0)
        finally:
            c2.close()
            storage.close()

    def test_retry_exhaustion_raises(self):
        """Verify OperationalError is raised if max_retries are exceeded."""
        storage = SQLiteStorage(self.db_path, timeout=0.01, max_retries=2, retry_delay=0.01)
        r = Receipt(
            index=0,
            timestamp="2026-11-26T12:00:00Z",
            agent_id="test-agent",
            event_type="test",
            data={"val": 1},
            metadata={},
            prev_hash="0" * 64,
            hash="h" * 64,
        )

        c2 = sqlite3.connect(self.db_path, isolation_level=None)
        try:
            c2.execute("BEGIN EXCLUSIVE;")
            with self.assertRaises(sqlite3.OperationalError):
                storage.append(r)
            c2.execute("COMMIT;")
        finally:
            c2.close()
            storage.close()

    def test_non_locked_operational_error_raises_immediately(self):
        """Verify non-lock OperationalError raises immediately without retrying."""
        storage = SQLiteStorage(self.db_path, max_retries=2)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                storage._execute_write("SYNTAX ERROR IN SQL;")
        finally:
            storage.close()

    def test_generic_exception_triggers_rollback(self):
        """Verify generic non-operational exceptions trigger rollback and re-raise."""
        storage = SQLiteStorage(self.db_path)
        try:
            with self.assertRaises(Exception):
                # Pass invalid params type that causes TypeError inside execute
                storage._execute_write("SELECT 1;", params="not_a_sequence_tuple")
        finally:
            storage.close()

    def test_setup_retry_on_locked(self):
        """Verify _setup retries when database is locked during initialization."""
        lock_path = Path(self.temp_dir.name) / "setup_lock.db"
        c2 = sqlite3.connect(lock_path, check_same_thread=False, isolation_level=None)
        try:
            c2.execute("BEGIN EXCLUSIVE;")
            t = threading.Timer(0.04, lambda: c2.execute("COMMIT;"))
            t.start()
            storage = SQLiteStorage(lock_path, timeout=0.05, max_retries=5, retry_delay=0.02)
            t.join()
            self.assertEqual(storage.count(), 0)
            storage.close()
        finally:
            c2.close()

    def test_setup_retry_exhaustion_raises(self):
        """Verify _setup raises OperationalError when max_retries are exceeded."""
        exhaust_path = Path(self.temp_dir.name) / "setup_exhaust.db"
        c2 = sqlite3.connect(exhaust_path, check_same_thread=False, isolation_level=None)
        try:
            c2.execute("BEGIN EXCLUSIVE;")
            with self.assertRaises(sqlite3.OperationalError):
                SQLiteStorage(exhaust_path, timeout=0.01, max_retries=1, retry_delay=0.01)
            c2.execute("COMMIT;")
        finally:
            c2.close()


if __name__ == "__main__":
    unittest.main()
