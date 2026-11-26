"""
Example: In-Memory Ephemeral Ledgers and Automated Chained Archive Rotation.

This example demonstrates:
1. Running an ultra-fast, zero-disk in-memory ledger (:memory:) in ephemeral environments (Lambda, Cloud Run).
2. Atomic one-call persistence (flush_to_disk) before container shutdown.
3. Automated chained ledger rotation when partitions reach capacity (max_records or max_bytes).
4. Full mathematical verification across the entire chain of rotated archives.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Allow direct execution from repository root without prior pip install
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from tezca import Ledger, verify_ledger_chain


def main() -> None:
    temp_dir = tempfile.TemporaryDirectory()
    base_dir = Path(temp_dir.name)

    print("================================================================================")
    print("TEZCA ENTERPRISE SUITE: In-Memory Execution & Chained Archive Rotation")
    print("================================================================================\n")

    # -------------------------------------------------------------------------
    # PART 1: In-Memory Ledger with Atomic Flush to Disk
    # -------------------------------------------------------------------------
    print("--- [Part 1] Ephemeral In-Memory Execution (:memory:) ---")
    mem_ledger = Ledger(path=":memory:", secret_key="serverless-key-2026")

    print("Recording micro-actions inside in-memory sandbox...")
    for step in range(5):
        mem_ledger.record(
            agent_id="ephemeral-agent",
            event_type="reasoning_step",
            data={"step_number": step, "compute_ms": 12.4},
        )

    print(f"Recorded {len(mem_ledger)} events entirely in RAM. Verified: {mem_ledger.verify(secret_key='serverless-key-2026')[0]}")

    persisted_path = base_dir / "flushed_session.db"
    print(f"Flushing state to disk atomically -> {persisted_path.name}")
    mem_ledger.flush_to_disk(persisted_path)

    with Ledger(path=persisted_path, secret_key="serverless-key-2026") as disk_session:
        valid, details = disk_session.verify(secret_key="serverless-key-2026")
        print(f"[OK] Persisted ledger verified from disk: {valid} ({details['verified_events']} events)\n")

    # -------------------------------------------------------------------------
    # PART 2: Automated Chained Archive Rotation
    # -------------------------------------------------------------------------
    print("--- [Part 2] Automated Chained Ledger Rotation ---")
    active_path = base_dir / "production_agent.db"
    archive_dir = base_dir / "cold_storage"

    # Configure ledger to rotate every 4 events
    print("Initializing ledger with max_records=4 and archive_dir...")
    prod_ledger = Ledger(
        path=active_path,
        max_records=4,
        archive_dir=archive_dir,
        archive_prefix="prod_audit",
    )

    print("Simulating high-throughput agent event stream (10 total events)...")
    for i in range(10):
        receipt = prod_ledger.record(
            agent_id="production-executor",
            event_type="api_gateway_call",
            data={"req_id": f"req-900{i}", "status": 200},
        )
        print(f"  Event #{receipt.index:02d} recorded (Hash: {receipt.hash[:16]}...)")

    archives = prod_ledger.get_archives()
    print(f"\n[Rotation Summary]")
    print(f"  Active Ledger Records: {len(prod_ledger)}")
    print(f"  Rotated Archives ({len(archives)}):")
    for arc in archives:
        print(f"    - {arc.name} ({arc.stat().st_size:,} bytes)")

    # -------------------------------------------------------------------------
    # PART 3: Verifying Cryptographic Continuity Across Entire Archive Chain
    # -------------------------------------------------------------------------
    print("\n--- [Part 3] Verifying Entire Archive Chain ---")
    chain_valid, chain_details = prod_ledger.verify_chain()
    print(f"Chain Verification Result: {'PASS' if chain_valid else 'FAIL'}")
    print(f"  Total Partitions Verified: {chain_details['total_archives']}")
    print(f"  Total Continuous Events:   {chain_details['total_events']}")
    print(f"  Final Chain Hash:          {chain_details['latest_hash']}")

    print("\n[SUCCESS] Ephemeral execution and chained archive rotation verified cleanly.")
    prod_ledger.close()
    temp_dir.cleanup()


if __name__ == "__main__":
    main()
