"""
Tests for automated ledger rotation, chained archiving, and multi-archive verification (TZ-FEAT-12).
Verifies cryptographic continuity across rotated partitions, byte/record triggers, and CLI commands.
"""

import sys
from pathlib import Path
import pytest

from tezca.cli import main as cli_main
from tezca.ledger import Ledger, verify_ledger_chain
from tezca.storage import JSONLStorage, SQLiteStorage, StorageBackend


def test_storage_backend_rotation_defaults():
    backend = StorageBackend()
    assert backend.genesis_hash == "0" * 64
    assert backend.genesis_index == 0
    assert backend.get_metadata("any_key") is None
    backend.set_metadata("key", "val")
    assert backend.byte_size() == 0


def test_manual_rotation_empty_and_memory():
    # Empty ledger returns None
    ledger = Ledger(path=":memory:")
    with pytest.raises(ValueError, match="Cannot rotate an in-memory ledger"):
        ledger.rotate()

    # Empty disk ledger returns None
    disk_ledger = Ledger(path="empty_test.db")
    try:
        assert disk_ledger.rotate() is None
    finally:
        disk_ledger.close()
        p = Path("empty_test.db")
        if p.exists():
            p.unlink()


def test_auto_rotation_by_max_records(tmp_path: Path):
    db_path = tmp_path / "app.db"
    archive_dir = tmp_path / "archives"

    ledger = Ledger(
        path=db_path,
        max_records=5,
        archive_dir=archive_dir,
        archive_prefix="app_audit",
    )

    # Record 12 events (should create 2 archives of 5 events each, leaving 2 in active db)
    for i in range(12):
        ledger.record(
            agent_id="agent-rotate",
            event_type="iteration",
            data={"counter": i},
        )

    archives = ledger.get_archives()
    assert len(archives) == 2
    assert archives[0].name == "app_audit.0001.db"
    assert archives[1].name == "app_audit.0002.db"

    # Active ledger has remaining 2 records
    assert len(ledger) == 2
    assert ledger.latest().data == {"counter": 11}

    # Verify each archive independently
    arc1 = Ledger(archives[0])
    assert len(arc1) == 5
    assert arc1.genesis_index == 0
    v1, d1 = arc1.verify()
    assert v1 is True

    arc2 = Ledger(archives[1])
    assert len(arc2) == 5
    assert arc2.genesis_index == 5
    assert arc2.genesis_hash == d1["latest_hash"]
    v2, d2 = arc2.verify()
    assert v2 is True

    # Active ledger verification
    v_act, d_act = ledger.verify()
    assert v_act is True
    assert ledger.genesis_index == 10
    assert ledger.genesis_hash == d2["latest_hash"]

    # Verify entire chain seamlessly
    chain_valid, chain_details = ledger.verify_chain()
    assert chain_valid is True
    assert chain_details["total_archives"] == 3
    assert chain_details["total_events"] == 12
    assert chain_details["latest_hash"] == ledger.latest().hash


def test_tamper_detection_in_rotated_archive(tmp_path: Path):
    db_path = tmp_path / "tamper_test.db"
    archive_dir = tmp_path / "archives"

    ledger = Ledger(
        path=db_path,
        max_records=4,
        archive_dir=archive_dir,
    )

    for i in range(8):
        ledger.record(
            agent_id="agent-sec",
            event_type="audit",
            data={"value": i},
        )

    archives = ledger.get_archives()
    assert len(archives) == 1
    archive_file = archives[0]

    # Verification before tamper
    assert ledger.verify_chain()[0] is True

    # Tamper with archive file by updating data_json in SQLite
    import sqlite3
    conn = sqlite3.connect(archive_file)
    conn.execute("UPDATE tezca_receipts SET data_json = '{\"tampered\": true}' WHERE index_num = 2;")
    conn.commit()
    conn.close()

    # Verify chain now fails
    valid, details = ledger.verify_chain()
    assert valid is False
    assert details["failed_archive"] == str(archive_file)
    assert "Hash integrity failed" in details["error"]


def test_jsonl_ledger_rotation(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"
    archive_dir = tmp_path / "archives"

    ledger = Ledger(
        path=log_path,
        max_records=3,
        archive_dir=archive_dir,
        archive_prefix="jsonl_audit",
    )

    for i in range(7):
        ledger.record(
            agent_id="jsonl-agent",
            event_type="step",
            data={"i": i},
        )

    archives = ledger.get_archives()
    assert len(archives) == 2
    assert len(ledger) == 1

    # Verify entire chain
    valid, details = ledger.verify_chain()
    assert valid is True
    assert details["total_events"] == 7

    # Close and reopen active JSONL ledger to verify persistence of metadata header
    ledger.close()
    reopened = Ledger(path=log_path)
    assert reopened.genesis_index == 6
    import json
    last_arc_hash = json.loads(archives[1].read_text().strip().split("\n")[-1])["hash"]
    assert reopened.genesis_hash == last_arc_hash
    assert len(reopened) == 1
    v_reopened, _ = reopened.verify()
    assert v_reopened is True


def test_rotation_by_max_bytes(tmp_path: Path):
    db_path = tmp_path / "bytes.db"
    ledger = Ledger(
        path=db_path,
        max_bytes=1000,  # small threshold
    )

    for i in range(15):
        ledger.record(
            agent_id="agent-bytes",
            event_type="bulk_payload",
            data={"heavy": "x" * 200, "idx": i},
        )

    # Rotation must have triggered at least once
    archives = ledger.get_archives()
    assert len(archives) >= 1

    valid, details = ledger.verify_chain()
    assert valid is True
    assert details["total_events"] == 15


def test_manual_rotation_with_custom_archive_path(tmp_path: Path):
    db_path = tmp_path / "manual.db"
    custom_archive = tmp_path / "custom_archive_01.db"

    ledger = Ledger(path=db_path)
    ledger.record(agent_id="agent-1", event_type="login", data={"user": "bob"})
    latest_r = ledger.latest()
    assert latest_r is not None

    result_path = ledger.rotate(archive_path=custom_archive)
    assert result_path == custom_archive
    assert custom_archive.exists()

    # Active ledger is now ready with new genesis
    assert len(ledger) == 0
    assert ledger.genesis_hash == latest_r.hash
    assert ledger.genesis_index == 1

    r2 = ledger.record(agent_id="agent-1", event_type="action", data={"run": True})
    assert r2.index == 1
    assert r2.prev_hash == latest_r.hash

    valid, details = verify_ledger_chain([custom_archive, db_path])
    assert valid is True
    assert details["total_events"] == 2


def test_signed_ledger_chain_verification(tmp_path: Path):
    db_path = tmp_path / "signed.db"
    secret = "my-chain-secret-key"

    ledger = Ledger(
        path=db_path,
        max_records=3,
        secret_key=secret,
        signer_id="keymaster",
    )

    for i in range(7):
        ledger.record(
            agent_id="sec-agent",
            event_type="signed_event",
            data={"step": i},
        )

    valid, details = ledger.verify_chain(secret_key=secret)
    assert valid is True
    assert details["total_events"] == 7

    # Wrong secret key fails verification
    valid_bad, details_bad = ledger.verify_chain(secret_key="wrong-key")
    assert valid_bad is False
    assert "Invalid cryptographic signature" in details_bad["error"]


def test_verify_ledger_chain_edge_cases(tmp_path: Path):
    # Empty paths list
    v_empty, d_empty = verify_ledger_chain([])
    assert v_empty is True
    assert d_empty["total_archives"] == 0

    # Non-existent file
    v_missing, d_missing = verify_ledger_chain([tmp_path / "missing.db"])
    assert v_missing is False
    assert "does not exist" in d_missing["error"]

    # Out of order files
    db1 = tmp_path / "c1.db"
    db2 = tmp_path / "c2.db"

    l1 = Ledger(path=db1)
    l1.record(agent_id="a", event_type="e", data={"step": 1})
    h1 = l1.latest().hash
    l1.close()

    l2 = Ledger(path=db2, initial_prev_hash=h1, initial_index=1)
    l2.record(agent_id="a", event_type="e", data={"step": 2})
    l2.close()

    # Reversing order breaks chain
    v_reversed, d_reversed = verify_ledger_chain([db2, db1])
    assert v_reversed is False


def test_cli_verify_chain_command(tmp_path: Path, capsys):
    db_path = tmp_path / "cli_chain.db"
    ledger = Ledger(path=db_path, max_records=3)
    for i in range(7):
        ledger.record(agent_id="cli-agent", event_type="cli_op", data={"k": i})
    ledger.close()

    archives = sorted(tmp_path.glob("cli_chain.*.db"))
    all_paths = [str(a) for a in archives] + [str(db_path)]

    # Success CLI invocation
    rc = cli_main(["verify-chain"] + all_paths)
    assert rc == 0
    captured = capsys.readouterr()
    assert "Chained archive integrity: INTACT" in captured.out

    # Missing file CLI invocation
    rc_missing = cli_main(["verify-chain", "non_existent.db"])
    assert rc_missing == 1
    captured_err = capsys.readouterr()
    assert "[ERROR] Archive file not found" in captured_err.err

    # Tampered file CLI invocation
    import sqlite3
    conn = sqlite3.connect(archives[0])
    conn.execute("UPDATE tezca_receipts SET data_json = '{\"tamper\": 1}' WHERE index_num = 0;")
    conn.commit()
    conn.close()

    rc_fail = cli_main(["verify-chain"] + all_paths)
    assert rc_fail == 1
    captured_fail = capsys.readouterr()
    assert "Chained integrity broken at archive" in captured_fail.err


def test_cli_verify_chain_exception_handling(monkeypatch, capsys):
    import tezca.ledger

    def mock_verify_chain(*args, **kwargs):
        raise RuntimeError("Disk read simulated fault")

    monkeypatch.setattr(tezca.ledger, "verify_ledger_chain", mock_verify_chain)
    # Target existing file
    p = Path("pyproject.toml")
    rc = cli_main(["verify-chain", str(p)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "[ERROR] Chain verification failed" in captured.err


def test_get_archives_edge_cases(tmp_path: Path):
    mem_ledger = Ledger(path=":memory:")
    assert mem_ledger.get_archives() == []
    assert SQLiteStorage(":memory:").byte_size() == 0

    ledger = Ledger(path=tmp_path / "somedir" / "test.db")
    ledger.archive_dir = tmp_path / "non_existent_sub_dir"
    assert ledger.get_archives() == []


def test_verify_ledger_chain_with_empty_archive(tmp_path: Path):
    empty_db = tmp_path / "empty.db"
    l_empty = Ledger(path=empty_db)
    l_empty.close()

    real_db = tmp_path / "real.db"
    l_real = Ledger(path=real_db)
    l_real.record(agent_id="ag", event_type="ev", data={"x": 1})
    l_real.close()

    valid, details = verify_ledger_chain([empty_db, real_db])
    assert valid is True
    assert details["total_events"] == 1


def test_jsonl_set_metadata_with_active_writer(tmp_path: Path):
    log_file = tmp_path / "active_writer.jsonl"
    storage = JSONLStorage(log_file)
    # Write a record to open writer
    ledger = Ledger(storage=storage)
    ledger.record(agent_id="a", event_type="e", data={"v": 10})

    # Now set metadata with active writer and existing lines
    storage.set_metadata("custom_tag", "tag_value")
    assert storage.get_metadata("custom_tag") == "tag_value"
    assert storage.byte_size() > 0

    # Ensure records are intact
    assert len(ledger) == 1
    assert ledger.latest().data == {"v": 10}
