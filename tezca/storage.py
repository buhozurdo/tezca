"""
Storage backends for tezca audit logs.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Iterator, Optional

from tezca.canonical import canonical_dumps
from tezca.receipt import Receipt


class StorageBackend:
    """Base interface for ledger storage backends."""

    def append(self, receipt: Receipt) -> None:
        raise NotImplementedError

    def get_latest(self) -> Optional[Receipt]:
        raise NotImplementedError

    def get_by_index(self, index: int) -> Optional[Receipt]:
        raise NotImplementedError

    def iter_all(self) -> Iterator[Receipt]:
        raise NotImplementedError

    def count(self) -> int:
        raise NotImplementedError

    def close(self) -> None:
        pass


class SQLiteStorage(StorageBackend):
    """
    High-performance, zero-dependency SQLite storage with WAL mode enabled.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            isolation_level=None,  # Autocommit mode with explicit transactions
        )
        self._setup()

    def _setup(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tezca_receipts (
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
                CREATE INDEX IF NOT EXISTS idx_tezca_agent
                ON tezca_receipts(agent_id);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_tezca_event_type
                ON tezca_receipts(event_type);
            """)

    def _row_to_receipt(self, row: tuple) -> Receipt:
        idx, ts, agent, ev_type, data_raw, meta_raw, prev_h, h = row
        return Receipt(
            index=idx,
            timestamp=ts,
            agent_id=agent,
            event_type=ev_type,
            data=json.loads(data_raw),
            metadata=json.loads(meta_raw),
            prev_hash=prev_h,
            hash=h,
        )

    def append(self, receipt: Receipt) -> None:
        data_json = canonical_dumps(receipt.data)
        meta_json = canonical_dumps(receipt.metadata)
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                INSERT INTO tezca_receipts (
                    index_num, timestamp, agent_id, event_type,
                    data_json, metadata_json, prev_hash, hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    receipt.index,
                    receipt.timestamp,
                    receipt.agent_id,
                    receipt.event_type,
                    data_json,
                    meta_json,
                    receipt.prev_hash,
                    receipt.hash,
                ),
            )

    def get_latest(self) -> Optional[Receipt]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT index_num, timestamp, agent_id, event_type,
                       data_json, metadata_json, prev_hash, hash
                FROM tezca_receipts
                ORDER BY index_num DESC
                LIMIT 1;
                """
            )
            row = cur.fetchone()
            return self._row_to_receipt(row) if row else None

    def get_by_index(self, index: int) -> Optional[Receipt]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT index_num, timestamp, agent_id, event_type,
                       data_json, metadata_json, prev_hash, hash
                FROM tezca_receipts
                WHERE index_num = ?;
                """,
                (index,),
            )
            row = cur.fetchone()
            return self._row_to_receipt(row) if row else None

    def iter_all(self) -> Iterator[Receipt]:
        # Using a dedicated cursor to stream sequentially
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT index_num, timestamp, agent_id, event_type,
                       data_json, metadata_json, prev_hash, hash
                FROM tezca_receipts
                ORDER BY index_num ASC;
                """
            )
            while True:
                rows = cur.fetchmany(500)
                if not rows:
                    break
                for row in rows:
                    yield self._row_to_receipt(row)

    def count(self) -> int:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM tezca_receipts;")
            return int(cur.fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class JSONLStorage(StorageBackend):
    """
    Append-only JSON Lines storage backend for plain-text logs.
    """

    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)
        self._lock = threading.Lock()
        if not self.file_path.exists():
            self.file_path.touch()

    def append(self, receipt: Receipt) -> None:
        payload = json.dumps(receipt.to_dict(), ensure_ascii=False) + "\n"
        with self._lock:
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(payload)

    def iter_all(self) -> Iterator[Receipt]:
        with self._lock:
            if not self.file_path.exists():
                return
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if clean:
                        yield Receipt.from_dict(json.loads(clean))

    def get_latest(self) -> Optional[Receipt]:
        last: Optional[Receipt] = None
        for r in self.iter_all():
            last = r
        return last

    def get_by_index(self, index: int) -> Optional[Receipt]:
        for r in self.iter_all():
            if r.index == index:
                return r
        return None

    def count(self) -> int:
        return sum(1 for _ in self.iter_all())
