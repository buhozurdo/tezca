"""
Tests for standalone cryptographic proof bundles (.tezcaproof).
"""

import json
import tempfile
import unittest
from pathlib import Path

from tezca.ledger import Ledger
from tezca.proof import ProofBundle


class TestProofBundle(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "proof_test.db"

        with Ledger(self.db_path) as ledger:
            for i in range(5):
                ledger.record(
                    agent_id="audit-agent",
                    event_type="action",
                    data={"step": i, "desc": f"Execution step {i}"},
                )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_export_and_verify_offline(self):
        proof_file = Path(self.temp_dir.name) / "event_2.tezcaproof"
        with Ledger(self.db_path) as ledger:
            bundle = ledger.export_proof(2, output_path=proof_file)

        self.assertTrue(proof_file.exists())
        self.assertEqual(bundle.receipt.index, 2)

        # Load completely standalone / offline without ledger DB
        loaded_bundle = ProofBundle.load(proof_file)
        valid, msg = loaded_bundle.verify()
        self.assertTrue(valid)
        self.assertIn("verified successfully", msg)

    def test_detect_receipt_payload_tampering(self):
        proof_file = Path(self.temp_dir.name) / "tampered.tezcaproof"
        with Ledger(self.db_path) as ledger:
            bundle = ledger.export_proof(1, output_path=proof_file)

        # Modify receipt data in the saved JSON file
        data = json.loads(proof_file.read_text(encoding="utf-8"))
        data["receipt"]["data"]["step"] = 99999
        proof_file.write_text(json.dumps(data), encoding="utf-8")

        tampered_bundle = ProofBundle.load(proof_file)
        valid, msg = tampered_bundle.verify()
        self.assertFalse(valid)
        self.assertIn("Receipt payload altered", msg)

    def test_detect_merkle_root_tampering(self):
        proof_file = Path(self.temp_dir.name) / "tampered_root.tezcaproof"
        with Ledger(self.db_path) as ledger:
            ledger.export_proof(3, output_path=proof_file)

        data = json.loads(proof_file.read_text(encoding="utf-8"))
        data["merkle_root"] = "0" * 64
        proof_file.write_text(json.dumps(data), encoding="utf-8")

        tampered_bundle = ProofBundle.load(proof_file)
        valid, msg = tampered_bundle.verify()
        self.assertFalse(valid)
        self.assertIn("does not match bundle merkle root", msg)

    def test_out_of_range_index(self):
        with Ledger(self.db_path) as ledger:
            with self.assertRaises(IndexError):
                ledger.export_proof(999)


if __name__ == "__main__":
    unittest.main()
