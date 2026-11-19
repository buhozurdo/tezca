"""
Core Ledger implementation managing hash-chained audit trails.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional, Union

from tezca.canonical import GENESIS_HASH, canonical_dumps, compute_receipt_hash
from tezca.merkle import MerkleProof, MerkleTree
from tezca.proof import ProofBundle
from tezca.receipt import Receipt
from tezca.storage import JSONLStorage, SQLiteStorage, StorageBackend


class Ledger:
    """
    Cryptographic hash-chained ledger for AI agent decisions and tool executions.
    Supports binary Merkle tree snapshots, standalone proof export, and HMAC signing.
    """

    def __init__(
        self,
        path: str | Path = "audit.db",
        storage: Optional[StorageBackend] = None,
        secret_key: Optional[Union[str, bytes]] = None,
        signer_id: Optional[str] = None,
    ):
        self.path = Path(path)
        self.secret_key = secret_key
        self.signer_id = signer_id

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
        secret_key: Optional[Union[str, bytes]] = None,
        signer_id: Optional[str] = None,
    ) -> Receipt:
        """
        Record and cryptographically seal an agent event in the ledger.
        Optionally signs the receipt using HMAC-SHA256 for author non-repudiation.
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

        effective_key = secret_key if secret_key is not None else self.secret_key
        effective_signer = signer_id if signer_id is not None else self.signer_id

        receipt_sig = None
        if effective_key is not None:
            dummy = Receipt(
                index=index,
                timestamp=ts,
                agent_id=agent_id,
                event_type=event_type,
                data=data,
                metadata=meta,
                prev_hash=prev_hash,
                hash=receipt_hash,
            )
            receipt_sig = dummy.compute_signature(effective_key)

        receipt = Receipt(
            index=index,
            timestamp=ts,
            agent_id=agent_id,
            event_type=event_type,
            data=data,
            metadata=meta,
            prev_hash=prev_hash,
            hash=receipt_hash,
            signature=receipt_sig,
            signer_id=effective_signer,
        )

        self.storage.append(receipt)
        return receipt

    def verify(self, secret_key: Optional[Union[str, bytes]] = None) -> tuple[bool, dict[str, Any]]:
        """
        Verify the mathematical integrity of the entire ledger hash chain.
        Optionally verifies HMAC signatures on all receipts if a secret_key is supplied.
        """
        count = 0
        expected_prev_hash = GENESIS_HASH
        latest_hash: Optional[str] = None
        effective_key = secret_key if secret_key is not None else self.secret_key

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

            # 4. Signature verification check (if required)
            if effective_key is not None:
                if not receipt.signature:
                    return False, {
                        "verified_events": count,
                        "failed_at_index": receipt.index,
                        "error": "Missing receipt signature under signed verification policy",
                    }
                if not receipt.verify_signature(effective_key):
                    return False, {
                        "verified_events": count,
                        "failed_at_index": receipt.index,
                        "error": "Invalid cryptographic signature",
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

    def export_proof(
        self,
        index: int,
        output_path: Optional[Union[str, Path]] = None,
    ) -> ProofBundle:
        """
        Export a standalone, self-contained cryptographic proof bundle (.tezcaproof).
        """
        receipt = self.storage.get_by_index(index)
        if receipt is None:
            raise IndexError(f"Receipt at index {index} not found in ledger")

        merkle_proof = self.get_merkle_proof(index)
        latest = self.storage.get_latest()
        latest_hash = latest.hash if latest is not None else GENESIS_HASH
        chain_len = self.storage.count()

        bundle = ProofBundle(
            schema_version="tezca-proof/v1",
            ledger_genesis=GENESIS_HASH,
            chain_length=chain_len,
            latest_hash=latest_hash,
            merkle_root=merkle_proof.root_hash,
            receipt=receipt,
            merkle_proof=merkle_proof,
        )

        if output_path is not None:
            bundle.save(output_path)

        return bundle

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
