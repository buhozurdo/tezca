"""
Core Ledger implementation managing hash-chained audit trails.
"""

from __future__ import annotations

import hmac
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, Optional, Union

if TYPE_CHECKING:
    from tezca.fork import ForkReport

from tezca.canonical import GENESIS_HASH, canonical_dumps, compute_receipt_hash
from tezca.events import AgentEvent
from tezca.merkle import MerkleProof, MerkleTree
from tezca.proof import ProofBundle
from tezca.receipt import Receipt, compute_hmac_signature
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
        timeout: float = 30.0,
    ):
        self.path = Path(path)
        self.timeout = float(timeout)
        self.secret_key: Optional[bytes] = (
            secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
        )
        self.signer_id = signer_id

        if storage is not None:
            self.storage = storage
        elif self.path.suffix.lower() == ".jsonl":
            self.storage = JSONLStorage(self.path)
        else:
            self.storage = SQLiteStorage(self.path, timeout=self.timeout)

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

        effective_key = (
            secret_key.encode("utf-8") if isinstance(secret_key, str) else (secret_key or self.secret_key)
        )
        effective_signer = signer_id if signer_id is not None else self.signer_id

        receipt_sig = None
        if effective_key is not None:
            receipt_sig = compute_hmac_signature(receipt_hash, effective_key)

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
            signer_id=effective_signer if receipt_sig is not None else None,
        )

        self.storage.append(receipt)
        return receipt

    def record_event(
        self,
        event: AgentEvent,
        timestamp: Optional[str] = None,
        secret_key: Optional[Union[str, bytes]] = None,
        signer_id: Optional[str] = None,
    ) -> Receipt:
        """
        Record a standardized AgentEvent dataclass in the ledger.
        """
        kwargs = event.to_record_kwargs()
        return self.record(
            agent_id=kwargs["agent_id"],
            event_type=kwargs["event_type"],
            data=kwargs["data"],
            metadata=kwargs["metadata"],
            timestamp=timestamp,
            secret_key=secret_key,
            signer_id=signer_id,
        )

    def verify(self, secret_key: Optional[Union[str, bytes]] = None) -> tuple[bool, dict[str, Any]]:
        """
        Verify the mathematical integrity of the entire ledger hash chain.
        Fast-paths verification using raw stored canonical fields without JSON deserialization overhead.
        Early exits immediately on any detected anomaly or tamper attempt.
        """
        count = 0
        expected_prev_hash = GENESIS_HASH
        latest_hash: Optional[str] = None
        effective_key = (
            secret_key.encode("utf-8") if isinstance(secret_key, str) else (secret_key or self.secret_key)
        )

        for idx, row in enumerate(self.storage.iter_raw()):
            idx_num, ts, agent, ev_type, data_raw, meta_raw, prev_h, h, sig, signer = row[:10]
            if idx_num != idx:
                return False, {
                    "verified_events": count,
                    "failed_at_index": idx_num,
                    "error": f"Index sequence mismatch: expected {idx}, got {idx_num}",
                }
            if prev_h != expected_prev_hash:
                return False, {
                    "verified_events": count,
                    "failed_at_index": idx_num,
                    "error": "Previous hash link broken",
                    "expected_prev_hash": expected_prev_hash,
                    "actual_prev_hash": prev_h,
                }
            calc_h = compute_receipt_hash(
                index=idx_num,
                timestamp=ts,
                agent_id=agent,
                event_type=ev_type,
                canonical_data=data_raw,
                canonical_metadata=meta_raw,
                prev_hash=prev_h,
            )
            if calc_h != h:
                return False, {
                    "verified_events": count,
                    "failed_at_index": idx_num,
                    "error": "Hash integrity failed (payload altered)",
                    "recorded_hash": h,
                }
            if effective_key is not None:
                if not sig:
                    return False, {
                        "verified_events": count,
                        "failed_at_index": idx_num,
                        "error": "Missing receipt signature under signed verification policy",
                    }
                expected_sig = compute_hmac_signature(h, effective_key)
                if not hmac.compare_digest(sig, expected_sig):
                    return False, {
                        "verified_events": count,
                        "failed_at_index": idx_num,
                        "error": "Invalid cryptographic signature",
                    }
            expected_prev_hash = h
            latest_hash = h
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
        return self.storage.get_tail(n)

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
        Generate and package a standalone verifiable cryptographic proof bundle (.tezcaproof).
        """
        receipt = self.storage.get_by_index(index)
        if receipt is None:
            raise IndexError(f"Receipt at index {index} does not exist in ledger.")

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

    def compare_with(self, other: Ledger) -> ForkReport:
        """
        Forensically compare this ledger against another replica to detect forks or divergence.
        """
        from tezca.fork import detect_fork

        return detect_fork(self, other)

    def detect_fork(self, other: Ledger) -> ForkReport:
        """
        Alias for compare_with.
        """
        return self.compare_with(other)

    def checkpoint(self, mode: str = "PASSIVE") -> tuple[int, int, int]:
        """
        Execute WAL checkpoint on the underlying SQLite database.
        Returns (0, 0, 0) for non-SQLite backends.
        """
        if isinstance(self.storage, SQLiteStorage):
            return self.storage.checkpoint(mode=mode)
        return (0, 0, 0)

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
