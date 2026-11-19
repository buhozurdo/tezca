"""
tezca: Zero-dependency, hash-chained forensic ledger for AI agents.
"""

from __future__ import annotations

from tezca.canonical import GENESIS_HASH, canonical_dumps, compute_receipt_hash
from tezca.ledger import Ledger
from tezca.receipt import Receipt
from tezca.storage import JSONLStorage, SQLiteStorage, StorageBackend

__version__ = "0.1.0"

__all__ = [
    "GENESIS_HASH",
    "JSONLStorage",
    "Ledger",
    "Receipt",
    "SQLiteStorage",
    "StorageBackend",
    "__version__",
    "canonical_dumps",
    "compute_receipt_hash",
]
