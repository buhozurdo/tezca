# Release v0.1.0

Initial public release of `tezca`, a zero-dependency, hash-chained forensic ledger for AI agents.

## Highlights

* **Zero Dependencies:** Built entirely with the Python standard library (`hashlib`, `json`, `sqlite3`, `dataclasses`, `datetime`, `argparse`). Compatible with Python 3.9+.
* **Tamper-Evident Hash Chaining:** Cryptographic event linking using SHA-256 and deterministic JSON canonicalization. Altering any field or byte invalidates the chain.
* **Sub-Millisecond Storage Engine:** High-performance local SQLite storage configured with Write-Ahead Logging (`WAL`) and `NORMAL` synchronous mode, plus optional append-only JSON Lines (`.jsonl`) support.
* **Built-in Forensic CLI:** Command-line tooling (`tezca verify`, `tezca tail`, `tezca export`, `tezca inspect`) for audit verification and inspection.
* **Framework Agnostic:** Easily integrates with any LLM provider, agent framework (LangGraph, CrewAI, AutoGen), or standalone Python agent.

## What is Included

* `tezca.Ledger`: Primary interface for recording and verifying agent actions.
* `tezca.Receipt`: Immutable dataclass representing a sealed event receipt.
* `tezca.canonical_dumps` and `tezca.compute_receipt_hash`: Deterministic payload canonicalization and SHA-256 digest computation.
* `tezca.storage.SQLiteStorage` and `tezca.storage.JSONLStorage`: Persistent storage backends.
* CLI entry points `tezca` and `python -m tezca`.
* Runnable examples in `examples/`.
* Complete unit test suite with 100% pass rate.

## Installation

```bash
pip install tezca==0.1.0
```
