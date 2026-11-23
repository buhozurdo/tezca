"""
Example: Fork, Split-Chain, and Replay Detection across Distributed Agent Ledgers.

This example simulates:
1. An authoritative primary ledger operating in a cloud cluster.
2. An edge replica operating offline that diverged from common history.
3. Automated forensic divergence detection pinpointing the fork index and common ancestor.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Allow direct execution from repository root without prior pip install
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from tezca import Ledger, detect_fork


def main() -> None:
    temp_dir = tempfile.TemporaryDirectory()
    base_path = Path(temp_dir.name)

    primary_path = base_path / "primary_cluster.db"
    replica_path = base_path / "edge_replica.db"

    print("================================================================================")
    print("TEZCA FORENSIC SUITE: Distributed Agent Replica Divergence Analysis")
    print("================================================================================\n")

    # Step 1: Record common shared genesis and early history
    common_ts_0 = "2026-11-23T08:00:00Z"
    common_ts_1 = "2026-11-23T08:05:00Z"

    with Ledger(primary_path) as primary, Ledger(replica_path) as replica:
        print("[1] Seeding shared common ancestor history across primary and edge replica...")
        primary.record(
            agent_id="planner-agent",
            event_type="workflow_init",
            data={"job_id": "job-890", "target": "portfolio_rebalance"},
            timestamp=common_ts_0,
        )
        replica.record(
            agent_id="planner-agent",
            event_type="workflow_init",
            data={"job_id": "job-890", "target": "portfolio_rebalance"},
            timestamp=common_ts_0,
        )

        primary.record(
            agent_id="risk-agent",
            event_type="risk_approval",
            data={"max_slippage": 0.005, "status": "approved"},
            timestamp=common_ts_1,
        )
        replica.record(
            agent_id="risk-agent",
            event_type="risk_approval",
            data={"max_slippage": 0.005, "status": "approved"},
            timestamp=common_ts_1,
        )

    # Step 2: Compare when in-sync
    with Ledger(primary_path) as primary, Ledger(replica_path) as replica:
        report_sync = detect_fork(primary, replica)
        print(f"Initial State Check: {report_sync.summary()}\n")

    # Step 3: Divergence! Primary executes approved trade; Edge replica diverges due to network partition
    print("[2] Simulating network partition and conflicting branch decisions...")
    with Ledger(primary_path) as primary:
        primary.record(
            agent_id="execution-agent",
            event_type="order_submitted",
            data={"exchange": "primary-market", "order_id": "ORD-001", "qty": 500},
            timestamp="2026-11-23T08:10:00Z",
        )
        primary.record(
            agent_id="settlement-agent",
            event_type="order_filled",
            data={"order_id": "ORD-001", "fill_price": 142.50},
            timestamp="2026-11-23T08:10:30Z",
        )

    with Ledger(replica_path) as replica:
        # Edge replica executed locally on an alternate exchange
        replica.record(
            agent_id="execution-agent",
            event_type="order_submitted",
            data={"exchange": "dark-pool-backup", "order_id": "ORD-999-ROGUE", "qty": 500},
            timestamp="2026-11-23T08:10:00Z",
        )

    # Step 4: Run forensic comparison
    print("[3] Performing forensic split-chain analysis...")
    with Ledger(primary_path) as primary, Ledger(replica_path) as replica:
        report_fork = primary.compare_with(replica)

        print("\n--- FORENSIC FORK REPORT ---")
        print(f"Status:               {report_fork.status.upper()}")
        print(f"Compatible:           {report_fork.is_compatible}")
        print(f"Fork Detected:        {report_fork.is_forked}")
        print(f"Genesis Match:        {report_fork.genesis_match}")
        print(f"Common Ancestor:      Index #{report_fork.common_ancestor_index} (Hash: {(report_fork.common_ancestor_hash or '')[:16]}...)")
        print(f"Divergence Index:     Index #{report_fork.divergence_index}")
        print(f"Primary Div Hash:     {report_fork.primary_divergent_hash}")
        print(f"Replica Div Hash:     {report_fork.replica_divergent_hash}")
        print(f"Primary Divergent Ev: {report_fork.primary_divergent_summary}")
        print(f"Replica Divergent Ev: {report_fork.replica_divergent_summary}")
        print(f"\nVerdict: {report_fork.summary()}\n")

    temp_dir.cleanup()


if __name__ == "__main__":
    main()
