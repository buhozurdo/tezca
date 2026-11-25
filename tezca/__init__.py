"""
tezca: Zero-dependency, hash-chained forensic ledger for AI agents.
"""

from __future__ import annotations

from tezca.canonical import (
    GENESIS_HASH,
    canonical_dumps,
    compute_receipt_hash,
    get_canonical_serializer,
    set_canonical_serializer,
)
from tezca.events import AgentEvent, AgentEventType
from tezca.fork import ForkReport, ForkStatus, detect_fork, detect_forks
from tezca.integrations.interceptors import track_agent_call, wrap_completion, wrap_tool
from tezca.integrations.langchain import TezcaCallbackHandler
from tezca.ledger import Ledger
from tezca.merkle import MerkleProof, MerkleStep, MerkleTree
from tezca.proof import PROOF_SCHEMA_VERSION, ProofBundle
from tezca.receipt import Receipt
from tezca.report import ComplianceEvaluation, ComplianceReport, generate_compliance_report
from tezca.storage import JSONLStorage, SQLiteStorage, StorageBackend

__version__ = "0.4.1"

__all__ = [
    "AgentEvent",
    "AgentEventType",
    "ComplianceEvaluation",
    "ComplianceReport",
    "ForkReport",
    "ForkStatus",
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
    "detect_fork",
    "detect_forks",
    "generate_compliance_report",
    "get_canonical_serializer",
    "set_canonical_serializer",
    "track_agent_call",
    "wrap_completion",
    "wrap_tool",
]
