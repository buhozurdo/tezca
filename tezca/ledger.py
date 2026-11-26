"""
Core Ledger implementation managing hash-chained audit trails.
"""

from __future__ import annotations

import hmac
import threading
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
        max_records: Optional[int] = None,
        max_bytes: Optional[int] = None,
        archive_dir: Optional[Union[str, Path]] = None,
        archive_prefix: Optional[str] = None,
        initial_prev_hash: Optional[str] = None,
        initial_index: Optional[int] = None,
    ):
        str_path = str(path)
        self.is_memory = str_path == ":memory:" or "mode=memory" in str_path
        self.path = Path(path)
        self.timeout = float(timeout)
        self.max_records = int(max_records) if max_records is not None else None
        self.max_bytes = int(max_bytes) if max_bytes is not None else None
        self.archive_dir = Path(archive_dir) if archive_dir is not None else None
        self.archive_prefix = archive_prefix or (self.path.stem if not self.is_memory else "audit")
        self.secret_key: Optional[bytes] = (
            secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
        )
        self.signer_id = signer_id
        self._lock = threading.RLock()

        if storage is not None:
            self.storage = storage
            self.is_memory = getattr(storage, "is_memory", False)
        elif self.is_memory:
            self.storage = SQLiteStorage(":memory:", timeout=self.timeout)
        elif self.path.suffix.lower() == ".jsonl":
            self.storage = JSONLStorage(self.path)
        else:
            self.storage = SQLiteStorage(self.path, timeout=self.timeout)

        if initial_prev_hash is not None:
            self.storage.set_metadata("genesis_hash", initial_prev_hash)
        if initial_index is not None:
            self.storage.set_metadata("genesis_index", str(initial_index))

    @property
    def genesis_hash(self) -> str:
        """Hash linking this ledger to its parent archive or GENESIS_HASH."""
        return self.storage.genesis_hash

    @property
    def genesis_index(self) -> int:
        """Initial record sequence index for this ledger partition."""
        return self.storage.genesis_index

    def _should_rotate(self) -> bool:
        if self.is_memory:
            return False
        if self.max_records is not None and self.storage.count() >= self.max_records:
            return True
        if self.max_bytes is not None and self.storage.byte_size() >= self.max_bytes:
            return True
        return False

    def rotate(self, archive_path: Optional[Union[str, Path]] = None) -> Optional[Path]:
        """
        Rotate the current ledger to an archive file and link the new file's genesis
        to the last recorded receipt's hash.
        Returns the Path of the archived file, or None if the ledger is empty.
        """
        with self._lock:
            if self.is_memory:
                raise ValueError("Cannot rotate an in-memory ledger (:memory:).")

            latest = self.storage.get_latest()
            if latest is None:
                return None

            last_hash = latest.hash
            last_index = latest.index

            # Checkpoint WAL if SQLite
            if isinstance(self.storage, SQLiteStorage):
                self.storage.checkpoint(mode="TRUNCATE")

            self.storage.close()

            target_dir = self.archive_dir or self.path.parent
            target_dir.mkdir(parents=True, exist_ok=True)

            if archive_path is not None:
                dest = Path(archive_path)
            else:
                num = 1
                suffix = self.path.suffix
                while True:
                    candidate = target_dir / f"{self.archive_prefix}.{num:04d}{suffix}"
                    if not candidate.exists():
                        dest = candidate
                        break
                    num += 1

            import shutil
            shutil.move(str(self.path), str(dest))

            # Reopen fresh storage at self.path
            if self.path.suffix.lower() == ".jsonl":
                self.storage = JSONLStorage(self.path)
            else:
                self.storage = SQLiteStorage(self.path, timeout=self.timeout)

            # Cryptographically link new storage's genesis to previous archive's last hash
            self.storage.set_metadata("genesis_hash", last_hash)
            self.storage.set_metadata("genesis_index", str(last_index + 1))
            self.storage.set_metadata("parent_archive", dest.name)

            return dest

    def get_archives(self) -> list[Path]:
        """Return all historical archive files ordered sequentially."""
        if self.is_memory:
            return []
        target_dir = self.archive_dir or self.path.parent
        if not target_dir.exists():
            return []
        pattern = f"{self.archive_prefix}.*{self.path.suffix}"
        matches = sorted(target_dir.glob(pattern))
        return [m for m in matches if m.resolve() != self.path.resolve()]

    def verify_chain(
        self,
        secret_key: Optional[Union[str, bytes]] = None,
    ) -> tuple[bool, dict[str, Any]]:
        """Verify the full cryptographic chain across all rotated archives plus active ledger."""
        all_paths = self.get_archives()
        if self.path.exists() and self.storage.count() > 0:
            all_paths.append(self.path)
        return verify_ledger_chain(all_paths, secret_key=secret_key)

    def flush_to_disk(self, target_path: str | Path) -> None:
        """
        Persist the ledger state to an on-disk SQLite or JSONL file.
        For in-memory ledgers (:memory:), this enables ultra-fast execution in ephemeral
        environments (AWS Lambda, Google Cloud Run) with a zero-loss atomic persistence step.
        """
        self.storage.flush_to_disk(target_path)

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
        with self._lock:
            if self._should_rotate():
                self.rotate()

            latest = self.storage.get_latest()
            prev_hash = latest.hash if latest is not None else self.genesis_hash
            index = (latest.index + 1) if latest is not None else self.genesis_index

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

    def verify(
        self,
        secret_key: Optional[Union[str, bytes]] = None,
        expected_genesis_hash: Optional[str] = None,
    ) -> tuple[bool, dict[str, Any]]:
        """
        Verify the mathematical integrity of the entire ledger hash chain.
        Fast-paths verification using raw stored canonical fields without JSON deserialization overhead.
        Early exits immediately on any detected anomaly or tamper attempt.
        """
        count = 0
        expected_prev_hash = expected_genesis_hash or self.genesis_hash
        latest_hash: Optional[str] = None
        effective_key = (
            secret_key.encode("utf-8") if isinstance(secret_key, str) else (secret_key or self.secret_key)
        )
        start_index = self.genesis_index

        for idx, row in enumerate(self.storage.iter_raw()):
            idx_num, ts, agent, ev_type, data_raw, meta_raw, prev_h, h, sig, signer = row[:10]
            expected_idx = start_index + idx
            if idx_num != expected_idx:
                return False, {
                    "verified_events": count,
                    "failed_at_index": idx_num,
                    "error": f"Index sequence mismatch: expected {expected_idx}, got {idx_num}",
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
            "genesis_hash": expected_genesis_hash or self.genesis_hash,
            "latest_hash": latest_hash or (expected_genesis_hash or self.genesis_hash),
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


def verify_ledger_chain(
    paths: list[str | Path],
    secret_key: Optional[Union[str, bytes]] = None,
) -> tuple[bool, dict[str, Any]]:
    """
    Forensically verify an ordered chain of rotated ledger archives.
    Confirms that each archive's genesis mathematically links to the previous archive's final receipt hash.
    """
    if not paths:
        return True, {"total_archives": 0, "total_events": 0, "latest_hash": GENESIS_HASH}

    total_events = 0
    expected_prev = GENESIS_HASH
    last_archive_hash = GENESIS_HASH

    for p in paths:
        path_obj = Path(p)
        if not path_obj.exists():
            return False, {
                "failed_archive": str(p),
                "error": f"Archive file does not exist: {p}",
            }
        with Ledger(path=path_obj) as ledger:
            if len(ledger) == 0:
                continue
            valid, details = ledger.verify(secret_key=secret_key, expected_genesis_hash=expected_prev)
            if not valid:
                return False, {
                    "failed_archive": str(p),
                    "error": details.get("error", "Integrity check failed"),
                    "details": details,
                }
            expected_prev = details["latest_hash"]
            last_archive_hash = details["latest_hash"]
            total_events += details["verified_events"]

    return True, {
        "total_archives": len(paths),
        "total_events": total_events,
        "latest_hash": last_archive_hash,
    }
