"""
Immutable receipt representation for tezca forensic records.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import asdict, dataclass
from typing import Any, Optional

from tezca.canonical import canonical_dumps, compute_receipt_hash


@dataclass(frozen=True)
class Receipt:
    """
    Cryptographically sealed receipt representing an immutable agent event.
    Optionally signed with an HMAC or asymmetric key for non-repudiation.
    """

    index: int
    timestamp: str
    agent_id: str
    event_type: str
    data: Any
    metadata: dict[str, Any]
    prev_hash: str
    hash: str
    signature: Optional[str] = None
    signer_id: Optional[str] = None

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

    def compute_signature(self, secret_key: str | bytes) -> str:
        """
        Calculate the HMAC-SHA256 signature over this receipt's hash.
        """
        key_bytes = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
        return hmac.new(key_bytes, self.hash.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_signature(self, secret_key: str | bytes) -> bool:
        """
        Verify that this receipt's signature matches the secret key using constant-time comparison.
        """
        if not self.signature:
            return False
        expected = self.compute_signature(secret_key)
        return hmac.compare_digest(self.signature, expected)

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
            signature=d.get("signature"),
            signer_id=d.get("signer_id"),
        )
