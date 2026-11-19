"""
Tests for standalone cryptographic proof bundles (.tezcaproof).
"""

import json
import tempfile
import unittest
from pathlib import Path

from tezca.canonical import GENESIS_HASH
from tezca.ledger import Ledger
from tezca.merkle import MerkleProof, MerkleStep
from tezca.proof import ProofBundle
from tezca.receipt import Receipt


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
            ledger.export_proof(1, output_path=proof_file)

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

    def test_unsupported_schema_version(self):
        with Ledger(self.db_path) as ledger:
            bundle = ledger.export_proof(0)

        bad_schema_bundle = ProofBundle(
            schema_version="tezca-proof/v999",
            ledger_genesis=bundle.ledger_genesis,
            chain_length=bundle.chain_length,
            latest_hash=bundle.latest_hash,
            merkle_root=bundle.merkle_root,
            receipt=bundle.receipt,
            merkle_proof=bundle.merkle_proof,
        )
        valid, msg = bad_schema_bundle.verify()
        self.assertFalse(valid)
        self.assertIn("Unsupported schema version", msg)

    def test_invalid_genesis_hash(self):
        with Ledger(self.db_path) as ledger:
            bundle = ledger.export_proof(0)

        bad_genesis = ProofBundle(
            schema_version=bundle.schema_version,
            ledger_genesis="bad_genesis" * 4,
            chain_length=bundle.chain_length,
            latest_hash=bundle.latest_hash,
            merkle_root=bundle.merkle_root,
            receipt=bundle.receipt,
            merkle_proof=bundle.merkle_proof,
        )
        valid, msg = bad_genesis.verify()
        self.assertFalse(valid)
        self.assertIn("Invalid genesis hash", msg)

    def test_secret_key_requested_without_signature(self):
        with Ledger(self.db_path) as ledger:
            bundle = ledger.export_proof(0)

        valid, msg = bundle.verify(secret_key="some-key")
        self.assertFalse(valid)
        self.assertIn("receipt has no signature", msg)

    def test_leaf_hash_mismatch(self):
        with Ledger(self.db_path) as ledger:
            bundle = ledger.export_proof(0)

        bad_proof = MerkleProof(
            leaf_index=bundle.merkle_proof.leaf_index,
            leaf_hash="1" * 64,
            root_hash=bundle.merkle_proof.root_hash,
            steps=bundle.merkle_proof.steps,
        )
        bad_bundle = ProofBundle(
            schema_version=bundle.schema_version,
            ledger_genesis=bundle.ledger_genesis,
            chain_length=bundle.chain_length,
            latest_hash=bundle.latest_hash,
            merkle_root=bundle.merkle_root,
            receipt=bundle.receipt,
            merkle_proof=bad_proof,
        )
        valid, msg = bad_bundle.verify()
        self.assertFalse(valid)
        self.assertIn("does not match receipt hash", msg)

    def test_merkle_path_failure(self):
        with Ledger(self.db_path) as ledger:
            bundle = ledger.export_proof(0)

        corrupt_steps = [MerkleStep("left", "0" * 64)]
        corrupt_proof = MerkleProof(
            leaf_index=bundle.merkle_proof.leaf_index,
            leaf_hash=bundle.merkle_proof.leaf_hash,
            root_hash=bundle.merkle_proof.root_hash,
            steps=corrupt_steps,
        )
        corrupt_bundle = ProofBundle(
            schema_version=bundle.schema_version,
            ledger_genesis=bundle.ledger_genesis,
            chain_length=bundle.chain_length,
            latest_hash=bundle.latest_hash,
            merkle_root=bundle.merkle_root,
            receipt=bundle.receipt,
            merkle_proof=corrupt_proof,
        )
        valid, msg = corrupt_bundle.verify()
        self.assertFalse(valid)
        self.assertIn("Merkle audit path failed", msg)

    def test_out_of_range_index(self):
        with Ledger(self.db_path) as ledger:
            with self.assertRaises(IndexError):
                ledger.export_proof(999)


if __name__ == "__main__":
    unittest.main()
