"""
Self-contained cryptographic proof bundles (.tezcaproof) for third-party compliance verification.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional, Union

from tezca.canonical import GENESIS_HASH
from tezca.merkle import MerkleProof
from tezca.receipt import Receipt

PROOF_SCHEMA_VERSION = "tezca-proof/v1"


@dataclass(frozen=True)
class ProofBundle:
    """
    Self-contained, portable cryptographic proof demonstrating an immutable agent record.
    Can be audited offline without access to the original SQLite database.
    """

    schema_version: str
    ledger_genesis: str
    chain_length: int
    latest_hash: str
    merkle_root: str
    receipt: Receipt
    merkle_proof: MerkleProof

    def verify(self, secret_key: Optional[Union[str, bytes]] = None) -> tuple[bool, str]:
        """
        Verify the mathematical validity of this standalone proof bundle.
        Checks:
        1. Schema version compatibility.
        2. Genesis hash integrity.
        3. Receipt payload hash integrity.
        4. Optional HMAC signature verification if signed and secret_key is provided.
        5. Leaf-to-receipt hash match.
        6. Merkle root consistency.
        7. Merkle membership audit path validity.
        """
        if self.schema_version != PROOF_SCHEMA_VERSION:
            return False, f"Unsupported schema version: {self.schema_version}"

        if self.ledger_genesis != GENESIS_HASH:
            return False, f"Invalid genesis hash: expected {GENESIS_HASH}, got {self.ledger_genesis}"

        # 1. Receipt payload hash check
        if not self.receipt.verify_hash():
            return False, f"Receipt payload altered: hash {self.receipt.hash} does not match contents"

        # 2. Optional signature verification
        if secret_key is not None:
            if not self.receipt.signature:
                return False, "Verification requested secret_key but receipt has no signature"
            if not self.receipt.verify_signature(secret_key):
                return False, "Receipt signature verification failed"

        # 3. Merkle proof leaf match
        if self.merkle_proof.leaf_hash != self.receipt.hash:
            return False, (
                f"Merkle proof leaf ({self.merkle_proof.leaf_hash}) does not match "
                f"receipt hash ({self.receipt.hash})"
            )

        # 4. Merkle root match
        if self.merkle_proof.root_hash != self.merkle_root:
            return False, (
                f"Merkle proof root ({self.merkle_proof.root_hash}) does not match "
                f"bundle merkle root ({self.merkle_root})"
            )

        # 5. Merkle path verification
        if not self.merkle_proof.verify():
            return False, "Merkle audit path failed to reconstruct root hash"

        return True, "Cryptographic proof verified successfully."

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "ledger_genesis": self.ledger_genesis,
            "chain_length": self.chain_length,
            "latest_hash": self.latest_hash,
            "merkle_root": self.merkle_root,
            "receipt": self.receipt.to_dict(),
            "merkle_proof": self.merkle_proof.to_dict(),
        }

    def save(self, path: Union[str, Path]) -> None:
        """Save this proof bundle to a JSON file (conventionally .tezcaproof)."""
        target = Path(path)
        payload = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        target.write_text(payload, encoding="utf-8")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ProofBundle:
        return cls(
            schema_version=str(d.get("schema_version", PROOF_SCHEMA_VERSION)),
            ledger_genesis=str(d.get("ledger_genesis", GENESIS_HASH)),
            chain_length=int(d["chain_length"]),
            latest_hash=str(d["latest_hash"]),
            merkle_root=str(d["merkle_root"]),
            receipt=Receipt.from_dict(d["receipt"]),
            merkle_proof=MerkleProof.from_dict(d["merkle_proof"]),
        )

    @classmethod
    def load(cls, path: Union[str, Path]) -> ProofBundle:
        """Load a proof bundle from a JSON file."""
        target = Path(path)
        content = target.read_text(encoding="utf-8")
        return cls.from_dict(json.loads(content))
