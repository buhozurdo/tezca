"""
Immutable receipt representation for tezca forensic records.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from tezca.canonical import canonical_dumps, compute_receipt_hash


@dataclass(frozen=True)
class Receipt:
    """
    Cryptographically sealed receipt representing an immutable agent event.
    """

    index: int
    timestamp: str
    agent_id: str
    event_type: str
    data: Any
    metadata: dict[str, Any]
    prev_hash: str
    hash: str

    def verify_hash(self) -> bool:
        """
        Verify that this receipt's hash matches its canonical contents.
        """
        expected = compute_receipt_hash(
            index=self.index,
            timestamp=self.timestamp,
            agent_id=self.agent_id,
            event_type=self.event_type,
            canonical_data=canonical_dumps(self.data),
            canonical_metadata=canonical_dumps(self.metadata),
            prev_hash=self.prev_hash,
        )
        return expected == self.hash

    def to_dict(self) -> dict[str, Any]:
        """
        Convert receipt to a dictionary.
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Receipt:
        """
        Reconstruct a receipt from a dictionary.
        """
        return cls(
            index=int(d["index"]),
            timestamp=str(d["timestamp"]),
            agent_id=str(d["agent_id"]),
            event_type=str(d["event_type"]),
            data=d["data"],
            metadata=dict(d.get("metadata") or {}),
            prev_hash=str(d["prev_hash"]),
            hash=str(d["hash"]),
        )
