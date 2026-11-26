"""
Tests for in-memory ledger (:memory:) and flush_to_disk persistence.
Verifies zero-disk operation, atomic backup serialization, and mathematical integrity.
"""

import threading
import pytest
from pathlib import Path

from tezca.ledger import Ledger
from tezca.receipt import Receipt
from tezca.storage import JSONLStorage, SQLiteStorage, StorageBackend


def test_storage_backend_base_defaults():
    backend = StorageBackend()
    assert backend.is_memory is False
    with pytest.raises(NotImplementedError):
        backend.flush_to_disk("out.db")


def test_in_memory_ledger_initialization():
    ledger = Ledger(path=":memory:")
    assert ledger.is_memory is True
    assert ledger.storage.is_memory is True
    assert isinstance(ledger.storage, SQLiteStorage)
    assert len(ledger) == 0
    assert ledger.latest() is None


def test_in_memory_storage_initialization():
    storage = SQLiteStorage(":memory:")
    assert storage.is_memory is True
    assert storage.count() == 0
    # Checkpoint on memory storage returns (0, 0, 0) safely
    assert storage.checkpoint() == (0, 0, 0)
    storage.close()


def test_in_memory_ledger_record_and_verify():
    ledger = Ledger(path=":memory:", secret_key="test-key", signer_id="agent-007")

    r0 = ledger.record(
        agent_id="agent-007",
        event_type="plan_generation",
        data={"goal": "deploy service"},
    )
    assert r0.index == 0
    assert r0.signature is not None
    assert r0.signer_id == "agent-007"

    r1 = ledger.record(
        agent_id="agent-007",
        event_type="tool_execution",
        data={"command": "terraform apply"},
    )
    assert r1.index == 1
    assert r1.prev_hash == r0.hash

    assert len(ledger) == 2
    assert ledger.latest().hash == r1.hash

    valid, details = ledger.verify(secret_key="test-key")
    assert valid is True
    assert details["verified_events"] == 2

    # Merkle tree & proof export
    tree = ledger.merkle_tree()
    assert tree.root is not None
    proof = ledger.get_merkle_proof(1)
    assert proof.verify(r1.hash) is True

    # Checkpoint call on ledger
    assert ledger.checkpoint() == (0, 0, 0)


def test_in_memory_flush_to_disk(tmp_path: Path):
    disk_path = tmp_path / "nested" / "persisted_audit.db"
    assert not disk_path.exists()

    ledger = Ledger(path=":memory:", secret_key="secret-123")
    for i in range(10):
        ledger.record(
            agent_id="test-agent",
            event_type=f"event-{i}",
            data={"counter": i, "state": "active"},
        )

    orig_root = ledger.merkle_root()
    orig_latest = ledger.latest()
    assert orig_latest is not None

    # Flush to disk (verifies nested directory creation)
    ledger.flush_to_disk(disk_path)
    assert disk_path.exists()

    # Open persisted ledger from disk and verify
    disk_ledger = Ledger(path=disk_path, secret_key="secret-123")
    assert disk_ledger.is_memory is False
    assert len(disk_ledger) == 10
    assert disk_ledger.latest().hash == orig_latest.hash
    assert disk_ledger.merkle_root() == orig_root

    valid, details = disk_ledger.verify(secret_key="secret-123")
    assert valid is True
    assert details["verified_events"] == 10

    # Ensure in-memory ledger continues functioning independently
    r10 = ledger.record(agent_id="test-agent", event_type="event-10", data={"counter": 10})
    assert len(ledger) == 11
    assert len(disk_ledger) == 10


def test_disk_to_disk_flush(tmp_path: Path):
    src_path = tmp_path / "src.db"
    dst_path = tmp_path / "dst.db"

    ledger = Ledger(path=src_path)
    ledger.record(agent_id="agent-1", event_type="test", data={"val": 42})
    ledger.flush_to_disk(dst_path)

    assert dst_path.exists()
    copy_ledger = Ledger(path=dst_path)
    assert len(copy_ledger) == 1
    assert copy_ledger.latest().data == {"val": 42}


def test_flush_to_disk_invalid_target():
    ledger = Ledger(path=":memory:")
    with pytest.raises(ValueError, match="must be a real disk path, not ':memory:'"):
        ledger.flush_to_disk(":memory:")

    with pytest.raises(ValueError, match="must be a real disk path, not ':memory:'"):
        ledger.storage.flush_to_disk("file::memory:?cache=shared")


def test_jsonl_flush_to_disk(tmp_path: Path):
    jsonl_src = tmp_path / "events.jsonl"
    jsonl_dst = tmp_path / "nested" / "backup_events.jsonl"

    ledger = Ledger(path=jsonl_src)
    assert ledger.is_memory is False
    assert ledger.storage.is_memory is False
    ledger.record(agent_id="agent-jsonl", event_type="login", data={"user": "alice"})
    ledger.flush_to_disk(jsonl_dst)

    assert jsonl_dst.exists()
    dst_ledger = Ledger(path=jsonl_dst)
    assert len(dst_ledger) == 1
    assert dst_ledger.latest().agent_id == "agent-jsonl"

    with pytest.raises(ValueError, match="must be a real disk path, not ':memory:'"):
        ledger.storage.flush_to_disk(":memory:")


def test_custom_storage_passed_to_ledger():
    mem_storage = SQLiteStorage(":memory:")
    ledger = Ledger(storage=mem_storage)
    assert ledger.is_memory is True

    disk_storage = SQLiteStorage("file::memory:?cache=shared")
    ledger2 = Ledger(storage=disk_storage)
    assert ledger2.is_memory is True


def test_concurrent_in_memory_appends():
    ledger = Ledger(path=":memory:")
    num_threads = 5
    records_per_thread = 20

    def worker(tid: int):
        for i in range(records_per_thread):
            ledger.record(
                agent_id=f"worker-{tid}",
                event_type="task_step",
                data={"tid": tid, "step": i},
            )

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(ledger) == num_threads * records_per_thread
    valid, details = ledger.verify()
    assert valid is True
    assert details["verified_events"] == num_threads * records_per_thread
