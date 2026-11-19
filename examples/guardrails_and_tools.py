"""
Example demonstrating how to record guardrail verdicts and high-risk actions.
"""

import sys
from pathlib import Path

# Allow direct execution from repository root without prior pip install
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from tezca import Ledger

def run_guardrails_example():
    db_file = Path("guardrails_audit.db")
    if db_file.exists():
        db_file.unlink()

    with Ledger(db_file) as ledger:
        # 1. User requests a sensitive action
        ledger.record(
            agent_id="banking-agent",
            event_type="user_prompt",
            data={"action": "wire_transfer", "amount_usd": 75000.0, "recipient_iban": "DE89370400440532013000"},
            metadata={"user_id": "cust_5541", "ip_address": "198.51.100.12"},
        )

        # 2. Guardrail evaluation
        ledger.record(
            agent_id="safety-guardrail",
            event_type="guardrail_verdict",
            data={
                "check_name": "anti_fraud_threshold",
                "verdict": "FLAG_FOR_2FA",
                "risk_score": 0.88,
                "reason": "Transfer amount exceeds daily single transaction threshold without step-up auth",
            },
            metadata={"guardrail_version": "v2.4"},
        )

        # 3. Agent blocks action pending confirmation
        ledger.record(
            agent_id="banking-agent",
            event_type="action_blocked",
            data={
                "action": "wire_transfer",
                "blocked_reason": "2FA required",
                "challenge_sent_to": "+1***4567",
            },
            metadata={"user_id": "cust_5541"},
        )

        valid, report = ledger.verify()
        print(f"[OK] Ledger verified: {report['verified_events']} events sealed in cryptographic chain.")

    if db_file.exists():
        db_file.unlink()

if __name__ == "__main__":
    run_guardrails_example()
