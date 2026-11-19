"""
Zero-dependency cryptographic Merkle Tree implementation for batch verification.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any, Sequence, Union

from tezca.canonical import GENESIS_HASH
from tezca.receipt import Receipt


def hash_pair(left: str, right: str) -> str:
    """
    Compute deterministic SHA-256 of two hashes.
    Uses colon separator to prevent second pre-image length ambiguities.
    """
    payload = f"{left}:{right}".encode("ascii")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class MerkleStep:
    """A single step in a Merkle audit path."""

    position: str  # "left" (sibling is on the left) or "right" (sibling is on the right)
    sibling_hash: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, str]) -> MerkleStep:
        return cls(position=str(d["position"]), sibling_hash=str(d["sibling_hash"]))


@dataclass(frozen=True)
class MerkleProof:
    """
    Cryptographic proof demonstrating membership of a specific receipt in a Merkle tree.
    Allows O(log N) verification of any event without inspecting the full ledger.
    """

    leaf_index: int
    leaf_hash: str
    root_hash: str
    steps: list[MerkleStep]

    def verify(self, expected_leaf_hash: str | None = None) -> bool:
        """
        Verify that recomputing hashes from leaf to root matches root_hash.
        """
        target = expected_leaf_hash if expected_leaf_hash is not None else self.leaf_hash
        if target != self.leaf_hash:
            return False

        current = target
        for step in self.steps:
            if step.position == "left":
                current = hash_pair(step.sibling_hash, current)
            elif step.position == "right":
                current = hash_pair(current, step.sibling_hash)
            else:
                return False

        return current == self.root_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash,
            "root_hash": self.root_hash,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MerkleProof:
        steps = [MerkleStep.from_dict(s) for s in d.get("steps", [])]
        return cls(
            leaf_index=int(d["leaf_index"]),
            leaf_hash=str(d["leaf_hash"]),
            root_hash=str(d["root_hash"]),
            steps=steps,
        )


class MerkleTree:
    """
    Binary Merkle Tree constructed over receipt hashes for sub-linear audit verification.
    """

    def __init__(self, elements: Sequence[Union[str, Receipt]]):
        self._leaves: list[str] = [
            elem.hash if isinstance(elem, Receipt) else str(elem)
            for elem in elements
        ]
        self._levels: list[list[str]] = []
        self._build_tree()

    def _build_tree(self) -> None:
        if not self._leaves:
            self._levels = [[GENESIS_HASH]]
            return

        current_level = list(self._leaves)
        self._levels = [current_level]

        while len(current_level) > 1:
            next_level: list[str] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Duplicate last odd node (standard Merkle tree balancing)
                    right = left
                next_level.append(hash_pair(left, right))
            self._levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        """The 64-character SHA-256 Merkle root hash."""
        return self._levels[-1][0] if self._levels and self._levels[-1] else GENESIS_HASH

    @property
    def leaf_count(self) -> int:
        """Total number of leaves in the tree."""
        return len(self._leaves)

    def get_proof(self, index: int) -> MerkleProof:
        """
        Generate a minimal Merkle audit path for the leaf at index.
        """
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"Leaf index {index} out of range [0, {len(self._leaves) - 1}]")

        target_leaf = self._leaves[index]
        steps: list[MerkleStep] = []
        idx = index

        for level_idx in range(len(self._levels) - 1):
            level = self._levels[level_idx]
            is_right_child = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right_child else idx + 1

            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx]
            else:
                # Sibling was duplicated from self
                sibling_hash = level[idx]

            position = "left" if is_right_child else "right"
            steps.append(MerkleStep(position=position, sibling_hash=sibling_hash))
            idx //= 2

        return MerkleProof(
            leaf_index=index,
            leaf_hash=target_leaf,
            root_hash=self.root,
            steps=steps,
        )
