"""
Storage backends for tezca audit logs.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterator, Optional

from tezca.canonical import canonical_dumps
from tezca.receipt import Receipt

_SQL_SELECT_FIELDS = (
    "SELECT index_num, timestamp, agent_id, event_type, "
    "data_json, metadata_json, prev_hash, hash, signature, signer_id "
    "FROM tezca_receipts"
)


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

    def iter_raw(self) -> Iterator[tuple]:
        """Stream raw stored fields to enable fast-path cryptographic verification."""
        for r in self.iter_all():
            yield (
                r.index,
                r.timestamp,
                r.agent_id,
                r.event_type,
                canonical_dumps(r.data),
                canonical_dumps(r.metadata),
                r.prev_hash,
                r.hash,
                r.signature,
                r.signer_id,
            )

    def get_tail(self, n: int = 10) -> list[Receipt]:
        """Fetch the last n receipts."""
        all_r = list(self.iter_all())
        return all_r[-n:] if n > 0 else []

    def count(self) -> int:
        raise NotImplementedError

    def close(self) -> None:
        pass


class SQLiteStorage(StorageBackend):
    """
    High-performance, zero-dependency SQLite storage with WAL mode enabled.
    Hardened for multi-process concurrency, automated retry backoff, and busy timeout management.
    """

    def __init__(
        self,
        db_path: str | Path,
        timeout: float = 30.0,
        max_retries: int = 5,
        retry_delay: float = 0.05,
    ):
        self.db_path = str(db_path)
        self.timeout = float(timeout)
        self.max_retries = int(max_retries)
        self.retry_delay = float(retry_delay)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self.db_path,
            timeout=self.timeout,
            check_same_thread=False,
            isolation_level=None,  # Autocommit mode with explicit transactions
        )
        self._setup()

    def _setup(self) -> None:
        import random
        import time

        for attempt in range(self.max_retries + 1):
            with self._lock:
                cur = self._conn.cursor()
                try:
                    mode = cur.execute("PRAGMA journal_mode;").fetchone()
                    if not mode or str(mode[0]).lower() != "wal":
                        cur.execute("PRAGMA journal_mode=WAL;")
                    cur.execute("PRAGMA synchronous=NORMAL;")
                    cur.execute("PRAGMA cache_size=-64000;")
                    cur.execute("PRAGMA temp_store=MEMORY;")
                    busy_timeout_ms = max(1000, int(self.timeout * 1000))
                    cur.execute(f"PRAGMA busy_timeout={busy_timeout_ms};")
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS tezca_receipts (
                            index_num INTEGER PRIMARY KEY,
                            timestamp TEXT NOT NULL,
                            agent_id TEXT NOT NULL,
                            event_type TEXT NOT NULL,
                            data_json TEXT NOT NULL,
                            metadata_json TEXT NOT NULL,
                            prev_hash TEXT NOT NULL,
                            hash TEXT NOT NULL UNIQUE,
                            signature TEXT,
                            signer_id TEXT
                        );
                    """)
                    # Auto-migrate v0.1.0 tables missing signature columns
                    try:
                        cur.execute("ALTER TABLE tezca_receipts ADD COLUMN signature TEXT;")
                    except sqlite3.OperationalError:
                        pass
                    try:
                        cur.execute("ALTER TABLE tezca_receipts ADD COLUMN signer_id TEXT;")
                    except sqlite3.OperationalError:
                        pass

                    cur.execute("""
                        CREATE INDEX IF NOT EXISTS idx_tezca_agent
                        ON tezca_receipts(agent_id);
                    """)
                    cur.execute("""
                        CREATE INDEX IF NOT EXISTS idx_tezca_event_type
                        ON tezca_receipts(event_type);
                    """)
                    return
                except sqlite3.OperationalError as ex:
                    err_msg = str(ex).lower()
                    if ("locked" in err_msg or "busy" in err_msg) and attempt < self.max_retries:
                        jitter = random.uniform(0.01, 0.05)
                        time.sleep((self.retry_delay * (2 ** attempt)) + jitter)
                        continue
                    raise

    def _row_to_receipt(self, row: tuple) -> Receipt:
        idx, ts, agent, ev_type, data_raw, meta_raw, prev_h, h = row[:8]
        sig = row[8] if len(row) > 8 else None
        signer = row[9] if len(row) > 9 else None
        return Receipt(
            index=idx,
            timestamp=ts,
            agent_id=agent,
            event_type=ev_type,
            data=json.loads(data_raw),
            metadata=json.loads(meta_raw),
            prev_hash=prev_h,
            hash=h,
            signature=sig,
            signer_id=signer,
        )

    def _execute_write(self, sql: str, params: tuple = ()) -> None:
        """Execute a write statement inside an immediate transaction with automated retry."""
        import random
        import time

        for attempt in range(self.max_retries + 1):
            with self._lock:
                cur = self._conn.cursor()
                in_tx = False
                try:
                    cur.execute("BEGIN IMMEDIATE;")
                    in_tx = True
                    cur.execute(sql, params)
                    cur.execute("COMMIT;")
                    return
                except sqlite3.OperationalError as ex:
                    if in_tx:
                        cur.execute("ROLLBACK;")
                    err_msg = str(ex).lower()
                    if ("locked" in err_msg or "busy" in err_msg) and attempt < self.max_retries:
                        jitter = random.uniform(0.005, 0.02)
                        time.sleep((self.retry_delay * (2 ** attempt)) + jitter)
                        continue
                    raise
                except Exception:
                    if in_tx:
                        cur.execute("ROLLBACK;")
                    raise

    def append(self, receipt: Receipt) -> None:
        data_json = canonical_dumps(receipt.data)
        meta_json = canonical_dumps(receipt.metadata)
        self._execute_write(
            """
            INSERT INTO tezca_receipts (
                index_num, timestamp, agent_id, event_type,
                data_json, metadata_json, prev_hash, hash,
                signature, signer_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                receipt.signature,
                receipt.signer_id,
            ),
        )

    def get_latest(self) -> Optional[Receipt]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(f"{_SQL_SELECT_FIELDS} ORDER BY index_num DESC LIMIT 1;")
            row = cur.fetchone()
            return self._row_to_receipt(row) if row else None

    def get_by_index(self, index: int) -> Optional[Receipt]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(f"{_SQL_SELECT_FIELDS} WHERE index_num = ?;", (index,))
            row = cur.fetchone()
            return self._row_to_receipt(row) if row else None

    def iter_all(self) -> Iterator[Receipt]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(f"{_SQL_SELECT_FIELDS} ORDER BY index_num ASC;")
            while True:
                rows = cur.fetchmany(500)
                if not rows:
                    break
                for row in rows:
                    yield self._row_to_receipt(row)

    def iter_raw(self) -> Iterator[tuple]:
        """Stream raw SQLite rows without JSON deserialization overhead."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(f"{_SQL_SELECT_FIELDS} ORDER BY index_num ASC;")
            while True:
                rows = cur.fetchmany(100)
                if not rows:
                    break
                for row in rows:
                    yield row

    def get_tail(self, n: int = 10) -> list[Receipt]:
        """Fetch the last n receipts directly via SQL LIMIT without scanning entire table."""
        if n <= 0:
            return []
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(f"{_SQL_SELECT_FIELDS} ORDER BY index_num DESC LIMIT ?;", (n,))
            rows = cur.fetchall()
            return [self._row_to_receipt(row) for row in reversed(rows)]

    def count(self) -> int:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM tezca_receipts;")
            return int(cur.fetchone()[0])

    def checkpoint(self, mode: str = "PASSIVE") -> tuple[int, int, int]:
        """
        Execute WAL checkpoint to sync WAL journal frames into main database file.
        Modes: PASSIVE, FULL, RESTART, TRUNCATE.
        Returns: (busy, log_frames, checkpointed_frames).
        """
        valid_modes = {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}
        target_mode = mode.upper()
        if target_mode not in valid_modes:
            raise ValueError(f"Invalid WAL checkpoint mode: '{mode}'. Must be one of {valid_modes}")
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(f"PRAGMA wal_checkpoint({target_mode});")
            row = cur.fetchone()
            return (int(row[0]), int(row[1]), int(row[2])) if row else (0, 0, 0)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class JSONLStorage(StorageBackend):
    """
    Append-only JSON Lines storage backend for plain-text logs with buffered I/O.
    """

    def __init__(self, file_path: str | Path, buffer_size: int = 65536, auto_flush: bool = False):
        self.file_path = Path(file_path)
        self.buffer_size = buffer_size
        self.auto_flush = auto_flush
        self._lock = threading.Lock()
        self._writer: Optional[Any] = None
        self._latest: Optional[Receipt] = None
        if not self.file_path.exists():
            self.file_path.touch()
        else:
            self._latest = self._read_latest_from_disk()

    def _read_latest_from_disk(self) -> Optional[Receipt]:
        last: Optional[Receipt] = None
        with open(self.file_path, "r", encoding="utf-8") as f:
            for line in f:
                clean = line.strip()
                if clean:
                    last = Receipt.from_dict(json.loads(clean))
        return last

    def _get_writer(self) -> Any:
        if self._writer is None or self._writer.closed:
            self._writer = open(self.file_path, "a", encoding="utf-8", buffering=self.buffer_size)
        return self._writer

    def append(self, receipt: Receipt) -> None:
        payload = json.dumps(receipt.to_dict(), ensure_ascii=False) + "\n"
        with self._lock:
            writer = self._get_writer()
            writer.write(payload)
            if self.auto_flush:
                writer.flush()
            self._latest = receipt

    def flush(self) -> None:
        with self._lock:
            if self._writer and not self._writer.closed:
                self._writer.flush()

    def close(self) -> None:
        with self._lock:
            if self._writer and not self._writer.closed:
                self._writer.flush()
                self._writer.close()
                self._writer = None

    def get_latest(self) -> Optional[Receipt]:
        with self._lock:
            return self._latest

    def iter_all(self) -> Iterator[Receipt]:
        with self._lock:
            if self._writer and not self._writer.closed:
                self._writer.flush()
            if not self.file_path.exists():
                return
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if clean:
                        yield Receipt.from_dict(json.loads(clean))

    def iter_raw(self) -> Iterator[tuple]:
        """Stream raw parsed rows for high-throughput verification."""
        with self._lock:
            if self._writer and not self._writer.closed:
                self._writer.flush()
            if not self.file_path.exists():
                return
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if clean:
                        d = json.loads(clean)
                        yield (
                            d["index"],
                            d["timestamp"],
                            d["agent_id"],
                            d["event_type"],
                            canonical_dumps(d["data"]),
                            canonical_dumps(d["metadata"]),
                            d["prev_hash"],
                            d["hash"],
                            d.get("signature"),
                            d.get("signer_id"),
                        )

    def get_by_index(self, index: int) -> Optional[Receipt]:
        for r in self.iter_all():
            if r.index == index:
                return r
        return None

    def get_tail(self, n: int = 10) -> list[Receipt]:
        all_r = list(self.iter_all())
        return all_r[-n:] if n > 0 else []

    def count(self) -> int:
        return sum(1 for _ in self.iter_all())
