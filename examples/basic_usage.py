"""
Basic usage example for tezca.

Demonstrates initializing a ledger, recording events, and verifying chain integrity.
"""

import sys
from pathlib import Path

# Allow direct execution from repository root without prior pip install
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from tezca import Ledger

def run_example():
    db_file = Path("example_audit.db")
    if db_file.exists():
        db_file.unlink()

    print("1. Initializing ledger...")
    with Ledger(db_file) as ledger:
        # Record an incoming prompt
        r0 = ledger.record(
            agent_id="support-agent-42",
            event_type="prompt",
            data={"user_query": "Please upgrade my subscription plan."},
            metadata={"session_id": "sess_9001", "model": "gpt-4o"},
        )
        print(f"Recorded event #{r0.index} [prompt]: hash={r0.hash[:16]}...")

        # Record a tool execution
        r1 = ledger.record(
            agent_id="support-agent-42",
            event_type="tool_call",
            data={
                "tool_name": "update_subscription",
                "parameters": {"user_id": "usr_102", "new_tier": "enterprise"},
                "status": "success",
            },
            metadata={"session_id": "sess_9001"},
        )
        print(f"Recorded event #{r1.index} [tool_call]: hash={r1.hash[:16]}... (prev={r1.prev_hash[:16]}...)")

        # Record agent output
        r2 = ledger.record(
            agent_id="support-agent-42",
            event_type="response",
            data={"reply": "Your account has been upgraded to Enterprise."},
            metadata={"session_id": "sess_9001"},
        )
        print(f"Recorded event #{r2.index} [response]: hash={r2.hash[:16]}...")

        print("\n2. Verifying ledger integrity...")
        is_valid, report = ledger.verify()
        print(f"Chain valid: {is_valid}")
        print(f"Total events verified: {report['verified_events']}")
        print(f"Latest chain hash:    {report['latest_hash']}")

    # Clean up generated example file
    if db_file.exists():
        db_file.unlink()

if __name__ == "__main__":
    run_example()
