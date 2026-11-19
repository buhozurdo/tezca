# tezca

**Zero-dependency, hash-chained forensic ledger for AI agents.**

[![PyPI version](https://img.shields.io/pypi/v/tezca.svg)](https://pypi.org/project/tezca/)
[![Python](https://img.shields.io/pypi/pyversions/tezca.svg)](https://pypi.org/project/tezca/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()

> *Named after **Tezcatlipoca** (the "Smoking Mirror") -- the obsidian mirror that reflects and records everything hidden.*

`tezca` is a lightweight, pure-Python library that creates **cryptographically sealed, tamper-evident receipts** for every prompt, tool call, and guardrail verdict your AI agents execute.

---

## Why tezca?

When an AI agent issues a refund, modifies a database, or summarizes a medical record, standard application logs are not enough. Logs can be altered, observability SaaS platforms add latency and vendor lock-in, and compliance auditors (SOC2, HIPAA, ISO 42001, EU AI Act) demand **verifiable proof** of what happened and why.

`tezca` provides verifiable integrity with classical cryptography and zero bloat:

* **Zero Dependencies:** Built 100% on the Python standard library (`hashlib`, `json`, `sqlite3`). No PyTorch, no heavy SDKs, no supply-chain bloat.
* **Tamper-Evident Hash Chaining:** Every event is canonicalized and sealed with SHA-256, mathematically linked to the preceding record hash. Altering a single byte invalidates the chain.
* **Sub-Millisecond Overhead:** Executes locally in `< 1ms` per event, making it suitable for serverless, edge, and high-throughput agent workflows.
* **Built-in Forensic CLI:** Verify audit trail integrity instantly using `tezca verify`.
* **Framework Agnostic:** Compatible with any LLM provider (OpenAI, Anthropic, Gemini, Ollama) and agent framework (LangGraph, CrewAI, AutoGen, or custom Python code).

---

## Installation

```bash
pip install tezca
```

---

## Quickstart

### Recording Agent Events

```python
from tezca import Ledger

# Initialize ledger (uses SQLite with WAL mode by default)
ledger = Ledger("audit.db")

# Record an agent decision or tool invocation
receipt = ledger.record(
    agent_id="finance-agent-01",
    event_type="tool_call",
    data={
        "action": "issue_refund",
        "order_id": "ord_9876",
        "amount_usd": 149.99,
        "recipient": "user@example.com"
    },
    metadata={
        "session_id": "sess_4f89a",
        "model": "gpt-4o"
    }
)

print(f"Recorded index: {receipt.index}")
print(f"Receipt hash:   {receipt.hash}")
print(f"Previous hash:  {receipt.prev_hash}")
```

### Verifying Chain Integrity Programmatically

```python
from tezca import Ledger

ledger = Ledger("audit.db")
is_valid, report = ledger.verify()

if is_valid:
    print(f"Ledger intact: {report['verified_events']} events verified.")
else:
    print(f"TAMPER DETECTED at index {report['failed_at_index']}: {report['error']}")
```

---

## Forensic CLI

`tezca` includes a built-in CLI for audits and CI/CD pipelines:

### Verify a Ledger

```bash
tezca verify audit.db
```

Output:
```text
[OK] 1,420 events verified.
[OK] Chain integrity: INTACT (Genesis: 00000000... -> Latest: e4b219af...)
```

If any byte in the database or JSON payload has been altered:
```text
[FAIL] Tampering detected at record #42
Expected prev_hash: 8f3c1a...
Computed hash:     d1490e...
Chain broken.
```

### Inspect the Latest Events

```bash
tezca tail audit.db -n 5
```

### Export Receipts to JSON Lines

```bash
tezca export audit.db --output audit.jsonl
```

---

## How It Works

1. **Deterministic Canonicalization:** Every event payload is canonicalized using deterministic JSON serialization (lexicographically sorted keys, standard separators, UTF-8 normalization) before hashing.
2. **SHA-256 Chaining:** Each record hashes `index + timestamp + agent_id + event_type + canonical_data + canonical_metadata + prev_hash`.
3. **Genesis Anchor:** The first event links to a known 64-zero genesis hash (`0000...0000`), establishing an unbroken lineage.
4. **Resilient Local Storage:** Default SQLite storage operates with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and `PRAGMA synchronous=NORMAL` for maximum performance and multi-process concurrency.

---

## Examples

Runnable scripts are provided in the `examples/` directory:

* `examples/basic_usage.py`: Basic ledger initialization, recording prompt/tool/response events, and verification.
* `examples/guardrails_and_tools.py`: Demonstrates compliance logging, safety guardrail verdicts, and blocked actions.
* `examples/tamper_demonstration.py`: Simulates out-of-band tampering in SQLite and demonstrates automatic tamper detection.

To run an example:
```bash
python examples/basic_usage.py
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
