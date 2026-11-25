"""
Unit tests for Merkle tree construction and O(log N) audit proof verification.
"""

import tempfile
import unittest
from pathlib import Path

from tezca.canonical import GENESIS_HASH
from tezca.ledger import Ledger
from tezca.merkle import MerkleProof, MerkleStep, MerkleTree, hash_pair


class TestMerkleTree(unittest.TestCase):
    def test_empty_tree(self):
        tree = MerkleTree([])
        self.assertEqual(tree.root, GENESIS_HASH)
        self.assertEqual(tree.leaf_count, 0)
        with self.assertRaises(IndexError):
            tree.get_proof(0)

    def test_single_leaf_tree(self):
        leaf = "a" * 64
        tree = MerkleTree([leaf])
        self.assertEqual(tree.root, leaf)
        self.assertEqual(tree.leaf_count, 1)

        proof = tree.get_proof(0)
        self.assertEqual(proof.leaf_hash, leaf)
        self.assertEqual(proof.root_hash, leaf)
        self.assertEqual(len(proof.steps), 0)
        self.assertTrue(proof.verify())

    def test_two_leaves_tree(self):
        h1 = "1" * 64
        h2 = "2" * 64
        tree = MerkleTree([h1, h2])
        expected_root = hash_pair(h1, h2)
        self.assertEqual(tree.root, expected_root)

        # Proof for leaf 0
        p0 = tree.get_proof(0)
        self.assertEqual(p0.steps, [MerkleStep("right", h2)])
        self.assertTrue(p0.verify())

        # Proof for leaf 1
        p1 = tree.get_proof(1)
        self.assertEqual(p1.steps, [MerkleStep("left", h1)])
        self.assertTrue(p1.verify())

    def test_odd_leaves_balancing(self):
        # 3 leaves: level 0 = [h0, h1, h2] -> level 1 = [pair(h0,h1), pair(h2,h2)]
        h0, h1, h2 = "0" * 64, "1" * 64, "2" * 64
        tree = MerkleTree([h0, h1, h2])
        parent01 = hash_pair(h0, h1)
        parent22 = hash_pair(h2, h2)
        expected_root = hash_pair(parent01, parent22)
        self.assertEqual(tree.root, expected_root)

        for i in range(3):
            proof = tree.get_proof(i)
            self.assertTrue(proof.verify())

    def test_arbitrary_sizes_and_proof_verification(self):
        for size in [4, 5, 8, 13, 16, 27]:
            leaves = [f"{i:064x}" for i in range(size)]
            tree = MerkleTree(leaves)

            for i in range(size):
                proof = tree.get_proof(i)
                self.assertTrue(proof.verify())
                self.assertFalse(proof.verify(expected_leaf_hash="f" * 64))

                # Tamper with proof steps
                if proof.steps:
                    tampered_step = MerkleStep(proof.steps[0].position, "bad" * 21 + "b")
                    bad_steps = [tampered_step] + list(proof.steps[1:])
                    bad_proof = MerkleProof(
                        leaf_index=proof.leaf_index,
                        leaf_hash=proof.leaf_hash,
                        root_hash=proof.root_hash,
                        steps=bad_steps,
                    )
                    self.assertFalse(bad_proof.verify())

    def test_proof_serialization_roundtrip(self):
        leaves = [f"{i:064x}" for i in range(7)]
        tree = MerkleTree(leaves)
        proof = tree.get_proof(3)

        d = proof.to_dict()
        restored = MerkleProof.from_dict(d)
        self.assertEqual(proof.leaf_index, restored.leaf_index)
        self.assertEqual(proof.leaf_hash, restored.leaf_hash)
        self.assertEqual(proof.root_hash, restored.root_hash)
        self.assertEqual(proof.steps, restored.steps)
        self.assertTrue(restored.verify())

    def test_binary_proof_serialization_roundtrip_and_errors(self):
        leaves = [f"{i:064x}" for i in range(11)]
        tree = MerkleTree(leaves)
        proof = tree.get_proof(5)

        raw_bytes = proof.to_bytes()
        self.assertIsInstance(raw_bytes, bytes)
        restored = MerkleProof.from_bytes(raw_bytes)

        self.assertEqual(proof.leaf_index, restored.leaf_index)
        self.assertEqual(proof.leaf_hash, restored.leaf_hash)
        self.assertEqual(proof.root_hash, restored.root_hash)
        self.assertEqual(len(proof.steps), len(restored.steps))
        for s1, s2 in zip(proof.steps, restored.steps):
            self.assertEqual(s1.position, s2.position)
            self.assertEqual(s1.sibling_hash, s2.sibling_hash)
        self.assertTrue(restored.verify())

        # Error handling: truncated header (< 70 bytes)
        with self.assertRaises(ValueError):
            MerkleProof.from_bytes(b"too_short")

        # Error handling: truncated step payload
        with self.assertRaises(ValueError):
            MerkleProof.from_bytes(raw_bytes[:75])

    def test_invalid_step_position_fails_verification(self):
        proof = MerkleProof(
            leaf_index=0,
            leaf_hash="a" * 64,
            root_hash="b" * 64,
            steps=[MerkleStep(position="invalid_pos", sibling_hash="c" * 64)],
        )
        self.assertFalse(proof.verify())

    def test_ledger_merkle_integration(self):
        temp_dir = tempfile.TemporaryDirectory()
        db_path = Path(temp_dir.name) / "merkle_audit.db"

        with Ledger(db_path) as ledger:
            for i in range(6):
                ledger.record(
                    agent_id="test-agent",
                    event_type="test_step",
                    data={"step_number": i},
                )

            self.assertEqual(len(ledger), 6)
            root = ledger.merkle_root()
            self.assertEqual(len(root), 64)

            # Verify Merkle proof for each record
            for idx in range(6):
                proof = ledger.get_merkle_proof(idx)
                self.assertEqual(proof.root_hash, root)
                self.assertTrue(proof.verify())

        temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
