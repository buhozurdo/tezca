"""
Core Ledger implementation managing hash-chained audit trails.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from tezca.canonical import GENESIS_HASH, canonical_dumps, compute_receipt_hash
from tezca.merkle import MerkleProof, MerkleTree
from tezca.receipt import Receipt
from tezca.storage import JSONLStorage, SQLiteStorage, StorageBackend


class Ledger:
    """
    Cryptographic hash-chained ledger for AI agent decisions and tool executions.
    """

    def __init__(
        self,
        path: str | Path = "audit.db",
        storage: Optional[StorageBackend] = None,
    ):
        self.path = Path(path)
        if storage is not None:
            self.storage = storage
        elif self.path.suffix.lower() == ".jsonl":
            self.storage = JSONLStorage(self.path)
        else:
            self.storage = SQLiteStorage(self.path)

    def record(
        self,
        agent_id: str,
        event_type: str,
        data: Any,
        metadata: Optional[dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> Receipt:
        """
        Record and cryptographically seal an agent event in the ledger.
        """
        latest = self.storage.get_latest()
        prev_hash = latest.hash if latest is not None else GENESIS_HASH
        index = (latest.index + 1) if latest is not None else 0

        ts = timestamp or datetime.now(timezone.utc).isoformat()
        meta = metadata if metadata is not None else {}

        canonical_data = canonical_dumps(data)
        canonical_meta = canonical_dumps(meta)

        receipt_hash = compute_receipt_hash(
            index=index,
            timestamp=ts,
            agent_id=agent_id,
            event_type=event_type,
            canonical_data=canonical_data,
            canonical_metadata=canonical_meta,
            prev_hash=prev_hash,
        )

        receipt = Receipt(
            index=index,
            timestamp=ts,
            agent_id=agent_id,
            event_type=event_type,
            data=data,
            metadata=meta,
            prev_hash=prev_hash,
            hash=receipt_hash,
        )

        self.storage.append(receipt)
        return receipt

    def verify(self) -> tuple[bool, dict[str, Any]]:
        """
        Verify the mathematical integrity of the entire ledger hash chain.
        """
        count = 0
        expected_prev_hash = GENESIS_HASH
        latest_hash: Optional[str] = None

        for idx, receipt in enumerate(self.storage.iter_all()):
            # 1. Sequential index check
            if receipt.index != idx:
                return False, {
                    "verified_events": count,
                    "failed_at_index": receipt.index,
                    "error": f"Index sequence mismatch: expected {idx}, got {receipt.index}",
                }

            # 2. Previous hash link check
            if receipt.prev_hash != expected_prev_hash:
                return False, {
                    "verified_events": count,
                    "failed_at_index": receipt.index,
                    "error": "Previous hash link broken",
                    "expected_prev_hash": expected_prev_hash,
                    "actual_prev_hash": receipt.prev_hash,
                }

            # 3. Payload integrity check (recomputes SHA-256)
            if not receipt.verify_hash():
                return False, {
                    "verified_events": count,
                    "failed_at_index": receipt.index,
                    "error": "Hash integrity failed (payload altered)",
                    "recorded_hash": receipt.hash,
                }

            expected_prev_hash = receipt.hash
            latest_hash = receipt.hash
            count += 1

        return True, {
            "verified_events": count,
            "genesis_hash": GENESIS_HASH,
            "latest_hash": latest_hash or GENESIS_HASH,
        }

    def latest(self) -> Optional[Receipt]:
        """Get the most recently recorded receipt."""
        return self.storage.get_latest()

    def tail(self, n: int = 10) -> list[Receipt]:
        """Retrieve the last n recorded receipts."""
        all_receipts = list(self.storage.iter_all())
        return all_receipts[-n:] if n > 0 else []

    def merkle_tree(self) -> MerkleTree:
        """Construct a Merkle tree over all recorded receipts."""
        return MerkleTree(list(self.storage.iter_all()))

    def merkle_root(self) -> str:
        """Return the current Merkle root hash of the ledger."""
        return self.merkle_tree().root

    def get_merkle_proof(self, index: int) -> MerkleProof:
        """
        Generate a verifiable Merkle membership proof for receipt at index.
        """
        tree = self.merkle_tree()
        return tree.get_proof(index)

    def __iter__(self) -> Iterator[Receipt]:
        return self.storage.iter_all()

    def __len__(self) -> int:
        return self.storage.count()

    def close(self) -> None:
        self.storage.close()

    def __enter__(self) -> Ledger:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
