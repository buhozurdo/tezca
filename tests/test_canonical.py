"""
Tests for canonical serialization and hash computation.
"""

import unittest

from tezca.canonical import GENESIS_HASH, canonical_dumps, compute_receipt_hash


class TestCanonical(unittest.TestCase):
    def test_canonical_dumps_key_sorting(self):
        d1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
        d2 = {"a": 2, "z": 1, "m": {"a": 4, "b": 3}}
        self.assertEqual(canonical_dumps(d1), canonical_dumps(d2))
        self.assertEqual(canonical_dumps(d1), '{"a":2,"m":{"a":4,"b":3},"z":1}')

    def test_canonical_dumps_separators_compact(self):
        data = {"key": "val", "arr": [1, 2, 3]}
        result = canonical_dumps(data)
        self.assertNotIn(": ", result)
        self.assertNotIn(", ", result)

    def test_compute_receipt_hash_reproducibility(self):
        h1 = compute_receipt_hash(
            index=0,
            timestamp="2026-11-19T00:00:00Z",
            agent_id="test-agent",
            event_type="prompt",
            canonical_data='{"msg":"hello"}',
            canonical_metadata="{}",
            prev_hash=GENESIS_HASH,
        )
        h2 = compute_receipt_hash(
            index=0,
            timestamp="2026-11-19T00:00:00Z",
            agent_id="test-agent",
            event_type="prompt",
            canonical_data='{"msg":"hello"}',
            canonical_metadata="{}",
            prev_hash=GENESIS_HASH,
        )
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)


if __name__ == "__main__":
    unittest.main()
