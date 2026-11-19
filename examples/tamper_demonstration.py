"""
Demonstration of tamper detection.

Shows how tezca detects an altered database record.
"""

import sqlite3
import sys
from pathlib import Path

# Allow direct execution from repository root without prior pip install
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from tezca import Ledger

def run_tamper_demo():
    db_file = Path("tamper_demo.db")
    if db_file.exists():
        db_file.unlink()

    print("1. Creating legitimate audit trail...")
    with Ledger(db_file) as ledger:
        ledger.record("finance-agent", "payout", {"recipient": "Alice", "amount": 100})
        ledger.record("finance-agent", "payout", {"recipient": "Bob", "amount": 200})
        ledger.record("finance-agent", "payout", {"recipient": "Charlie", "amount": 300})

        valid, report = ledger.verify()
        print(f"Initial state: valid={valid}, events={report['verified_events']}")

    print("\n2. Simulating unauthorized database tampering (altering Bob's payout to 90000)...")
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE tezca_receipts
        SET data_json = '{"amount":90000,"recipient":"Bob"}'
        WHERE index_num = 1;
        """
    )
    conn.commit()
    conn.close()

    print("\n3. Verifying ledger after tampering...")
    with Ledger(db_file) as ledger:
        valid, report = ledger.verify()
        print(f"Chain valid: {valid}")
        print(f"Tamper detected at record index: {report.get('failed_at_index')}")
        print(f"Reason: {report.get('error')}")

    if db_file.exists():
        db_file.unlink()

if __name__ == "__main__":
    run_tamper_demo()
