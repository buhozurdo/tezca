"""
Tests for HMAC signature sealing and non-repudiation in tezca.
"""

import tempfile
import unittest
from pathlib import Path

from tezca.ledger import Ledger


class TestSignatures(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "signed_audit.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_record_with_hmac_signature(self):
        secret = "super-secret-audit-key-2026"
        with Ledger(self.db_path, secret_key=secret, signer_id="finance-agent") as ledger:
            r0 = ledger.record("finance-agent", "transfer", {"amount": 500})
            r1 = ledger.record("finance-agent", "transfer", {"amount": 1000})

            self.assertIsNotNone(r0.signature)
            self.assertEqual(r0.signer_id, "finance-agent")
            self.assertTrue(r0.verify_signature(secret))
            self.assertFalse(r0.verify_signature("wrong-key"))

            # Receipt without signature returns False
            from tezca.receipt import Receipt
            unsigned = Receipt(index=99, timestamp="ts", agent_id="a", event_type="e", data={}, metadata={}, prev_hash="p", hash="h")
            self.assertFalse(unsigned.verify_signature(secret))

            # Reconstruct from dict without metadata
            reconstructed = Receipt.from_dict({"index": 99, "timestamp": "ts", "agent_id": "a", "event_type": "e", "data": {}, "prev_hash": "p", "hash": "h"})
            self.assertEqual(reconstructed.metadata, {})

            # Ledger verify with correct secret key
            valid, report = ledger.verify(secret_key=secret)
            self.assertTrue(valid)
            self.assertEqual(report["verified_events"], 2)

            # Ledger verify with wrong secret key fails
            valid_bad, report_bad = ledger.verify(secret_key="attacker-key")
            self.assertFalse(valid_bad)
            self.assertIn("Invalid cryptographic signature", report_bad["error"])

    def test_signed_proof_bundle_verification(self):
        secret = "company-private-signing-key"
        proof_file = Path(self.temp_dir.name) / "signed_event.tezcaproof"

        with Ledger(self.db_path, secret_key=secret, signer_id="sec-agent") as ledger:
            ledger.record("sec-agent", "login", {"user": "admin"})
            bundle = ledger.export_proof(0, output_path=proof_file)

        # 1. Standalone verification without key checks hash & Merkle
        valid_no_key, _ = bundle.verify()
        self.assertTrue(valid_no_key)

        # 2. Standalone verification with correct secret key validates author signature
        valid_with_key, msg = bundle.verify(secret_key=secret)
        self.assertTrue(valid_with_key)
        self.assertIn("verified successfully", msg)

        # 3. Standalone verification with wrong secret key fails
        valid_wrong_key, msg_wrong = bundle.verify(secret_key="counterfeit-key")
        self.assertFalse(valid_wrong_key)
        self.assertIn("signature verification failed", msg_wrong)


if __name__ == "__main__":
    unittest.main()
