"""
Demonstration of Merkle tree proofs, standalone proof bundle export, and HMAC signing.
"""

import sys
from pathlib import Path

# Allow direct execution from repository root without prior pip install
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from tezca import Ledger, ProofBundle


def run_proofs_example():
    db_file = Path("proofs_demo.db")
    proof_file = Path("refund_event.tezcaproof")

    for f in [db_file, proof_file]:
        if f.exists():
            f.unlink()

    signing_key = "secure-agent-key-2026"

    print("1. Recording signed agent events in ledger...")
    with Ledger(db_file, secret_key=signing_key, signer_id="finance-agent-01") as ledger:
        ledger.record("finance-agent-01", "prompt", {"query": "Refund order #401"})
        ledger.record("finance-agent-01", "guardrail_check", {"verdict": "APPROVED", "limit": 500})
        r_refund = ledger.record("finance-agent-01", "tool_call", {"action": "issue_refund", "order_id": 401, "usd": 85.50})
        ledger.record("finance-agent-01", "response", {"status": "Refund issued to customer."})

        print(f"Recorded 4 events. Chain verified: {ledger.verify(secret_key=signing_key)[0]}")
        print(f"Current Merkle Root: {ledger.merkle_root()[:24]}...")

        print("\n2. Exporting standalone cryptographic proof for refund tool call (event #2)...")
        bundle = ledger.export_proof(index=2, output_path=proof_file)
        print(f"Proof bundle exported to {proof_file} ({proof_file.stat().st_size} bytes)")

    print("\n3. Verifying proof bundle completely offline (without access to proofs_demo.db)...")
    loaded_bundle = ProofBundle.load(proof_file)
    valid, msg = loaded_bundle.verify(secret_key=signing_key)
    print(f"Proof Valid: {valid}")
    print(f"Verification Output: {msg}")
    print(f"Verified Event #{loaded_bundle.receipt.index} hash: {loaded_bundle.receipt.hash[:20]}...")
    print(f"Verified Signer ID: {loaded_bundle.receipt.signer_id}")

    # Clean up generated demo files
    for f in [db_file, proof_file]:
        if f.exists():
            f.unlink()


if __name__ == "__main__":
    run_proofs_example()
