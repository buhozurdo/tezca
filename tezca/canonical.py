"""
Canonical serialization and cryptographic hashing utilities for tezca.

All comments and documentation are in English.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Optional

GENESIS_HASH = "0" * 64

_CANONICAL_ENCODER = json.JSONEncoder(
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    default=str,
)

_CUSTOM_SERIALIZER: Optional[Callable[[Any], str]] = None


def set_canonical_serializer(serializer: Optional[Callable[[Any], str]]) -> None:
    """
    Register a custom high-performance serializer (e.g. orjson/ujson) for canonical JSON dumps.
    Pass None to reset back to standard library encoder.
    """
    global _CUSTOM_SERIALIZER
    _CUSTOM_SERIALIZER = serializer


def get_canonical_serializer() -> Optional[Callable[[Any], str]]:
    """Return currently active custom serializer or None."""
    return _CUSTOM_SERIALIZER


def canonical_dumps(obj: Any) -> str:
    """
    Produce a deterministic, compact JSON string using cached stdlib encoder or registered native serializer.
    
    Keys are sorted lexicographically, separators are minimal without spaces,
    and non-string keys/types fallback cleanly.
    """
    if _CUSTOM_SERIALIZER is not None:
        return _CUSTOM_SERIALIZER(obj)
    return _CANONICAL_ENCODER.encode(obj)


def compute_receipt_hash(
    index: int,
    timestamp: str,
    agent_id: str,
    event_type: str,
    canonical_data: str,
    canonical_metadata: str,
    prev_hash: str,
) -> str:
    """
    Calculate the SHA-256 digest of a receipt payload.
    
    The payload concatenates all fields with deterministic separators.
    """
    payload = (
        f"{index}\n"
        f"{timestamp}\n"
        f"{agent_id}\n"
        f"{event_type}\n"
        f"{canonical_data}\n"
        f"{canonical_metadata}\n"
        f"{prev_hash}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
