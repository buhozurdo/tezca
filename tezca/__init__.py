"""
tezca: Zero-dependency, hash-chained forensic ledger for AI agents.
"""

from __future__ import annotations

from tezca.canonical import GENESIS_HASH, canonical_dumps, compute_receipt_hash
from tezca.events import AgentEvent, AgentEventType
from tezca.integrations.interceptors import track_agent_call, wrap_completion, wrap_tool
from tezca.integrations.langchain import TezcaCallbackHandler
from tezca.ledger import Ledger
from tezca.merkle import MerkleProof, MerkleStep, MerkleTree
from tezca.proof import PROOF_SCHEMA_VERSION, ProofBundle
from tezca.receipt import Receipt
from tezca.storage import JSONLStorage, SQLiteStorage, StorageBackend

__version__ = "0.3.0"

__all__ = [
    "AgentEvent",
    "AgentEventType",
    "GENESIS_HASH",
    "JSONLStorage",
    "Ledger",
    "MerkleProof",
    "MerkleStep",
    "MerkleTree",
    "PROOF_SCHEMA_VERSION",
    "ProofBundle",
    "Receipt",
    "SQLiteStorage",
    "StorageBackend",
    "TezcaCallbackHandler",
    "__version__",
    "canonical_dumps",
    "compute_receipt_hash",
    "track_agent_call",
    "wrap_completion",
    "wrap_tool",
]
