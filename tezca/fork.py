"""
Fork, split-chain, and divergence anomaly detection for distributed agent ledgers.
Enables forensic verification of replica consistency, split-brain scenarios, and replay attacks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional, Sequence

if TYPE_CHECKING:
    from tezca.ledger import Ledger


class ForkStatus:
    IDENTICAL = "identical"
    REPLICA_AHEAD = "replica_ahead"
    REPLICA_BEHIND = "replica_behind"
    FORKED = "forked"
    DISJOINT = "disjoint"
    BOTH_EMPTY = "both_empty"
    PRIMARY_EMPTY = "primary_empty"
    REPLICA_EMPTY = "replica_empty"


@dataclass(frozen=True)
class ForkReport:
    """
    Forensic analysis report comparing two ledger histories (primary vs replica).
    Identifies common ancestors, divergence points, branch depths, and replay anomalies.
    """

    status: str
    is_forked: bool
    is_compatible: bool
    genesis_match: bool
    common_ancestor_index: Optional[int]
    common_ancestor_hash: Optional[str]
    divergence_index: Optional[int]
    primary_length: int
    replica_length: int
    primary_divergent_hash: Optional[str]
    replica_divergent_hash: Optional[str]
    primary_divergent_summary: Optional[dict[str, Any]]
    replica_divergent_summary: Optional[dict[str, Any]]
    replay_detected: bool = False
    replayed_indices: list[int] = field(default_factory=list)

    @property
    def is_identical(self) -> bool:
        """True if both ledgers have identical event histories or both are empty."""
        return self.status in (ForkStatus.IDENTICAL, ForkStatus.BOTH_EMPTY)

    def summary(self) -> str:
        """Return a human-readable forensic summary string."""
        if self.is_identical:
            if self.status == ForkStatus.BOTH_EMPTY:
                return "Both ledgers are empty. State: IN_SYNC (0 events)."
            tip = (self.common_ancestor_hash or "")[:16]
            return f"Ledgers are identical. State: IN_SYNC ({self.primary_length:,} events, Tip: {tip}...)."

        if self.status == ForkStatus.REPLICA_AHEAD:
            delta = self.replica_length - self.primary_length
            return (
                f"Replica is ahead of primary by {delta:,} event(s). "
                f"Valid linear extension (Primary: {self.primary_length:,}, Replica: {self.replica_length:,})."
            )

        if self.status == ForkStatus.REPLICA_BEHIND:
            delta = self.primary_length - self.replica_length
            return (
                f"Replica is behind primary by {delta:,} event(s). "
                f"Valid prefix chain (Primary: {self.primary_length:,}, Replica: {self.replica_length:,})."
            )

        if self.status == ForkStatus.PRIMARY_EMPTY:
            return f"Primary ledger is empty while replica contains {self.replica_length:,} event(s)."

        if self.status == ForkStatus.REPLICA_EMPTY:
            return f"Replica ledger is empty while primary contains {self.primary_length:,} event(s)."

        if self.status == ForkStatus.DISJOINT:
            return (
                f"Disjoint ledgers: Genesis hashes do not match. "
                f"Primary: {(self.primary_divergent_hash or '')[:16]}..., "
                f"Replica: {(self.replica_divergent_hash or '')[:16]}..."
            )

        replay_badge = " [REPLAY DETECTED]" if self.replay_detected else ""
        return (
            f"FORK DETECTED at index #{self.divergence_index}!{replay_badge} "
            f"Common ancestor: #{self.common_ancestor_index} ({(self.common_ancestor_hash or '')[:16]}...). "
            f"Primary diverged to {(self.primary_divergent_hash or '')[:16]}..., "
            f"Replica diverged to {(self.replica_divergent_hash or '')[:16]}... "
            f"(Primary depth: {self.primary_length:,}, Replica depth: {self.replica_length:,})."
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert report to serializable dictionary."""
        return {
            "status": self.status,
            "is_forked": self.is_forked,
            "is_compatible": self.is_compatible,
            "genesis_match": self.genesis_match,
            "common_ancestor_index": self.common_ancestor_index,
            "common_ancestor_hash": self.common_ancestor_hash,
            "divergence_index": self.divergence_index,
            "primary_length": self.primary_length,
            "replica_length": self.replica_length,
            "primary_divergent_hash": self.primary_divergent_hash,
            "replica_divergent_hash": self.replica_divergent_hash,
            "primary_divergent_summary": self.primary_divergent_summary,
            "replica_divergent_summary": self.replica_divergent_summary,
            "replay_detected": self.replay_detected,
            "replayed_indices": list(self.replayed_indices),
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        """Serialize report to canonical JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def _extract_summary(row: tuple[Any, ...]) -> dict[str, Any]:
    """Helper to extract event summary from raw storage row."""
    return {
        "index": row[0],
        "timestamp": row[1],
        "agent_id": row[2],
        "event_type": row[3],
        "hash": row[7],
    }


def detect_fork(primary: Ledger, replica: Ledger) -> ForkReport:
    """
    Forensically compare two ledgers to detect forks, split chains, or replay attacks.
    Uses high-speed raw streaming without deserializing event payloads.
    """
    p_iter = iter(primary.storage.iter_raw())
    r_iter = iter(replica.storage.iter_raw())

    p_count = 0
    r_count = 0
    common_idx: Optional[int] = None
    common_hash: Optional[str] = None
    div_idx: Optional[int] = None

    p_div_hash: Optional[str] = None
    r_div_hash: Optional[str] = None
    p_div_sum: Optional[dict[str, Any]] = None
    r_div_sum: Optional[dict[str, Any]] = None

    primary_hashes: dict[str, int] = {}
    replica_divergent_hashes: list[tuple[str, int]] = []

    # Stream simultaneously row by row
    while True:
        p_row = next(p_iter, None)
        r_row = next(r_iter, None)

        if p_row is None and r_row is None:
            break

        if p_row is not None:
            p_count += 1
            primary_hashes[p_row[7]] = p_row[0]

        if r_row is not None:
            r_count += 1

        if p_row is not None and r_row is not None:
            p_h = p_row[7]
            r_h = r_row[7]

            if div_idx is None:
                if p_h == r_h:
                    common_idx = p_row[0]
                    common_hash = p_h
                else:
                    div_idx = p_row[0]
                    p_div_hash = p_h
                    r_div_hash = r_h
                    p_div_sum = _extract_summary(p_row)
                    r_div_sum = _extract_summary(r_row)
                    replica_divergent_hashes.append((r_h, r_row[0]))
            else:
                replica_divergent_hashes.append((r_h, r_row[0]))

        elif r_row is not None and div_idx is not None:
            replica_divergent_hashes.append((r_row[7], r_row[0]))

    # Check for empty ledger edge cases
    if p_count == 0 and r_count == 0:
        return ForkReport(
            status=ForkStatus.BOTH_EMPTY,
            is_forked=False,
            is_compatible=True,
            genesis_match=True,
            common_ancestor_index=None,
            common_ancestor_hash=None,
            divergence_index=None,
            primary_length=0,
            replica_length=0,
            primary_divergent_hash=None,
            replica_divergent_hash=None,
            primary_divergent_summary=None,
            replica_divergent_summary=None,
        )

    if p_count == 0:
        return ForkReport(
            status=ForkStatus.PRIMARY_EMPTY,
            is_forked=False,
            is_compatible=False,
            genesis_match=False,
            common_ancestor_index=None,
            common_ancestor_hash=None,
            divergence_index=None,
            primary_length=0,
            replica_length=r_count,
            primary_divergent_hash=None,
            replica_divergent_hash=None,
            primary_divergent_summary=None,
            replica_divergent_summary=None,
        )

    if r_count == 0:
        return ForkReport(
            status=ForkStatus.REPLICA_EMPTY,
            is_forked=False,
            is_compatible=False,
            genesis_match=False,
            common_ancestor_index=None,
            common_ancestor_hash=None,
            divergence_index=None,
            primary_length=p_count,
            replica_length=0,
            primary_divergent_hash=None,
            replica_divergent_hash=None,
            primary_divergent_summary=None,
            replica_divergent_summary=None,
        )

    # Check if divergence occurred
    if div_idx is not None:
        is_disjoint = (div_idx == 0)
        replayed: list[int] = []
        for r_hash, r_idx in replica_divergent_hashes:
            if r_hash in primary_hashes:
                replayed.append(r_idx)

        return ForkReport(
            status=ForkStatus.DISJOINT if is_disjoint else ForkStatus.FORKED,
            is_forked=True,
            is_compatible=False,
            genesis_match=not is_disjoint,
            common_ancestor_index=common_idx,
            common_ancestor_hash=common_hash,
            divergence_index=div_idx,
            primary_length=p_count,
            replica_length=r_count,
            primary_divergent_hash=p_div_hash,
            replica_divergent_hash=r_div_hash,
            primary_divergent_summary=p_div_sum,
            replica_divergent_summary=r_div_sum,
            replay_detected=len(replayed) > 0,
            replayed_indices=replayed,
        )

    # No divergence within overlapping range: check lengths
    if p_count == r_count:
        status = ForkStatus.IDENTICAL
    elif r_count > p_count:
        status = ForkStatus.REPLICA_AHEAD
    else:
        status = ForkStatus.REPLICA_BEHIND

    return ForkReport(
        status=status,
        is_forked=False,
        is_compatible=True,
        genesis_match=True,
        common_ancestor_index=common_idx,
        common_ancestor_hash=common_hash,
        divergence_index=None,
        primary_length=p_count,
        replica_length=r_count,
        primary_divergent_hash=None,
        replica_divergent_hash=None,
        primary_divergent_summary=None,
        replica_divergent_summary=None,
    )


def detect_forks(primary: Ledger, replicas: Sequence[Ledger]) -> list[ForkReport]:
    """
    Compare multiple replica ledgers against a single authoritative primary ledger.
    """
    return [detect_fork(primary, replica) for replica in replicas]
