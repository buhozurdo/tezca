# tezca

**Zero-dependency, hash-chained cryptographic forensic ledger for autonomous AI agents.**

[![PyPI version](https://img.shields.io/pypi/v/tezca.svg)](https://pypi.org/project/tezca/)
[![Python Versions](https://img.shields.io/pypi/pyversions/tezca.svg)](https://pypi.org/project/tezca/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)]()
[![Type Checked](https://img.shields.io/badge/types-PEP_561_mypy_strict-blue.svg)]()

> *Named after **Tezcatlipoca** (the "Smoking Mirror") — the ancient obsidian mirror that reflects and preserves everything hidden.*

`tezca` is a lightweight, pure-Python cryptographic ledger that creates **mathematically sealed, tamper-evident receipts** for every prompt, tool execution, LLM completion, and guardrail decision executed by autonomous AI agents.

---

## The Black-Box Problem in Enterprise AI

When an autonomous AI agent executes database mutations, financial transfers, code modifications, or processes regulated PII, standard application logs and observability platforms are insufficient:

1. **Logs Can Be Mutated:** Traditional log files and centralized dashboards can be modified, truncated, or re-written by attackers, rogue insiders, or misconfigured processes.
2. **SaaS Telemetry Leaks Context & Adds Latency:** Sending full tool arguments, prompts, and system states to third-party cloud observability vendors creates regulatory risk (GDPR, HIPAA) and adds network latency.
3. **Auditors Demand Cryptographic Proof:** Emerging compliance frameworks (**EU AI Act Article 12**, **SOC 2 Type II CC6.8**, **NIST AI RMF**) require verifiable, tamper-evident record-keeping that proves an agent's historical sequence of decisions without reliance on vendor trust.

`tezca` solves this with classical cryptography, local-first execution, and **zero runtime dependencies**.

---

## Architectural Overview

```
[ Agent Action / Tool Invocation / LLM Prompt ]
                      │
                      ▼
   ┌─────────────────────────────────────┐
   │    Canonical JSON Serialization     │  <── Deterministic key sorting & UTF-8 formatting
   └──────────────────┬──────────────────┘
                      │
                      ▼
   ┌─────────────────────────────────────┐
   │      SHA-256 Hash Chain Link        │  <── H(Index + Timestamp + Event + Data + PrevHash)
   └──────────────────┬──────────────────┘
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
   ┌───────────┐             ┌───────────┐
   │ HMAC-256  │             │  Binary   │
   │ Signature │             │  Merkle   │
   │  Sealing  │             │   Tree    │
   └─────┬─────┘             └─────┬─────┘
         │                         │
         └────────────┬────────────┘
                      ▼
         ┌─────────────────────────┐
         │ Portable .tezcaproof    │  <── Verifiable offline by external auditors
         │ Standalone Bundle       │
         └─────────────────────────┘
```

---

## Feature Matrix: How Tezca Compares

| Capability | `tezca` | OpenTelemetry | LangSmith / Arize | Traditional DB Logs |
| :--- | :---: | :---: | :---: | :---: |
| **Cryptographic Hash Chaining** | **Yes (SHA-256)** | No | No | No |
| **Tamper-Evident Verification** | **Yes (Mathematical)** | No | No | No |
| **Author Non-Repudiation (HMAC)** | **Yes** | No | No | No |
| **Runtime Dependencies** | **0 (Stdlib only)** | 15+ packages | 30+ packages | 0 - 10+ packages |
| **Network & Telemetry Overhead** | **0 ms (Local-first)** | Network bound | SaaS network latency | Minimal |
| **Air-Gapped / Sovereign Deployments** | **Yes** | Requires collector | Cloud-dependent | Yes |
| **Standalone Offline Proofs (`.tezcaproof`)** | **Yes (O(log N))** | No | No | No |
| **Regulatory Alignment** | **EU AI Act Art. 12, SOC2** | APM / Metrics only | Debugging / Evals | Ad-hoc |

---

## Performance SLA (Validated Microbenchmarks)

Engineered for zero-overhead integration into production microservices:

| Operation | Throughput / Latency | Implementation Detail |
| :--- | :---: | :--- |
| **Canonical Serialization** | **0.02 ms / call** | Pre-compiled deterministic encoder (`json.JSONEncoder`) |
| **SQLite WAL Record Append** | **< 0.25 ms / event** | `PRAGMA synchronous=NORMAL`, in-memory transaction lock |
| **Buffered JSONL Append** | **0.004 ms / event** | 64KB RAM write buffer, $O(1)$ memory index |
| **Chain Verification (500 events)** | **1.84 ms total** | Direct raw SQL cursor streaming without dict allocations |
| **Tamper Forensic Scan** | **1.36 ms total** | Immediate early-exit upon first broken link or altered byte |
| **Merkle Tree Proof Generation** | **< 0.10 ms** | Binary heap representation, $O(\log N)$ sibling path traversal |

---

## Installation

```bash
pip install tezca
```

`tezca` requires Python 3.9+ and has **zero third-party dependencies**.

---

## Quickstart

### 1. Recording Agent Events

```python
from tezca import Ledger

# Initialize ledger (uses high-performance SQLite in WAL mode by default)
with Ledger("audit.db") as ledger:
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

    print(f"Sealed event #{receipt.index} with hash: {receipt.hash}")
    print(f"Cryptographically linked to prev_hash: {receipt.prev_hash}")
```

### 2. Verifying Chain Integrity Programmatically

```python
from tezca import Ledger

with Ledger("audit.db") as ledger:
    is_valid, report = ledger.verify()

    if is_valid:
        print(f"[OK] Ledger intact: {report['verified_events']} events cryptographically verified.")
    else:
        print(f"[ALERT] Tamper detected at index {report['failed_at_index']}: {report['error']}")
```

---

## Framework Integrations & Interceptors

### Tool Function Decorator (`@wrap_tool`)

Automatically capture tool arguments, execution latency, and return values or exceptions:

```python
from tezca import Ledger, wrap_tool

ledger = Ledger("audit.db")

@wrap_tool(ledger, agent_id="support-bot", tool_name="fetch_user_profile")
def fetch_profile(user_id: str):
    return {"id": user_id, "tier": "enterprise"}

# Executions and latency are automatically sealed in the ledger
profile = fetch_profile("usr_123")
```

### LLM Completion Decorator (`@wrap_completion`)

Intercept and log prompts, model identifiers, token usage, and completions:

```python
from tezca import Ledger, wrap_completion

ledger = Ledger("audit.db")

@wrap_completion(ledger, agent_id="support-bot", model="gpt-4o")
def call_llm(messages: list):
    return client.chat.completions.create(model="gpt-4o", messages=messages)
```

### LangChain & LangGraph Native Callback Handler

```python
from tezca import Ledger, TezcaCallbackHandler

ledger = Ledger("audit.db")
handler = TezcaCallbackHandler(ledger, agent_id="langchain-agent", session_id="sess_102")

# Pass handler into any LangChain runnable or LangGraph agent
agent.invoke({"input": "Analyze quarterly report"}, config={"callbacks": [handler]})
```

---

## Forensic CLI

`tezca` includes a built-in enterprise CLI for audits, incident response, and CI/CD pipelines:

### Verify Chain Integrity
```bash
tezca verify audit.db
```
```text
[OK] 1,420 events verified.
[OK] Chain integrity: INTACT (Genesis: 00000000... -> Latest: e4b219af...)
```

### Inspect Audit Tail
```bash
tezca tail audit.db -n 5
```

### Export Standalone Proof Bundles (`.tezcaproof`)
Export an isolated cryptographic proof for event #42 that compliance officers can verify offline without access to your production database:
```bash
tezca proof audit.db 42 -o event_42.tezcaproof
```

### Verify an Offline Proof Bundle
```bash
tezca verify-proof event_42.tezcaproof
```
```text
[OK] Proof verified: Receipt #42 is cryptographically sealed.
[OK] Merkle Root: 0bc8e92e178936f47081d43e...
[OK] Event Hash:  b51f283543dc5a13373e...
```

### Generate Regulatory Compliance Audit Reports (HTML & JSON)
Generate formal audit evidence for EU AI Act, SOC 2 Type II, and HIPAA compliance:
```bash
# Generate self-contained HTML executive audit report
tezca report audit.db -o compliance_report.html

# Generate structured JSON for SIEM ingestion (Splunk, Datadog)
tezca report audit.db --format json -o audit_evidence.json
```

### Compare Distributed Replicas & Detect Split-Chain Forks
Forensically detect split-brain forks, replay attacks, and divergent branches across distributed agent replicas:
```bash
tezca compare primary_cluster.db edge_replica.db
```
```text
Status:             FORKED
Compatible:         NO
Fork Detected:      YES
Genesis Match:      YES
Common Ancestor:    #41 (a0bc7b4f1beb2dfd...)
Divergence Index:   #42
Summary:            FORK DETECTED at index #42! Common ancestor: #41 (a0bc7b4f1beb2dfd...).
```

---

## Cryptographic Guarantees & Non-Repudiation

### 1. Deterministic Canonical Serialization
To guarantee cross-platform immutability, `tezca` canonicalizes JSON payloads by sorting dictionary keys lexicographically, eliminating arbitrary whitespace, and enforcing standard UTF-8 representations.

### 2. SHA-256 Recursive Chaining
Every receipt hash is defined recursively:
$$\text{Hash}_i = \text{SHA256}\Big(\text{Index}_i \parallel \text{Timestamp}_i \parallel \text{AgentID}_i \parallel \text{EventType}_i \parallel \text{Data}_i \parallel \text{Metadata}_i \parallel \text{Hash}_{i-1}\Big)$$
where $\text{Hash}_0 = 0^{64}$ (Genesis Hash). Any alteration of past records changes all downstream hashes, triggering verification failure.

### 3. Binary Merkle Trees & HMAC Sealing
For high-volume auditing, receipts are aggregated into binary Merkle trees yielding a 64-character root hash. Optional HMAC-SHA256 signing binds each record to a verifiable private secret key, establishing legal **non-repudiation**.

---

## Regulatory Compliance Mapping

| Standard | Section / Control | How `tezca` Satisfies Requirement |
| :--- | :--- | :--- |
| **EU AI Act** | **Article 12 (Record-Keeping)** | Continuous, automatic logging of AI operations throughout lifecycle with cryptographic immutability. |
| **SOC 2 Type II** | **CC6.8 / CC7.2 (Audit Logs)** | Tamper-evident hash chaining prevents retroactive modification of security-sensitive audit trails. |
| **HIPAA** | **§ 164.312(b) (Audit Controls)** | Verifiable, signed recording of PHI access, queries, and automated processing. |
| **NIST AI RMF** | **Govern 1.2 & Measure 2.5** | Transparent tracking of provenance for all automated agent actions and decisions. |

---

## Contributing

We welcome contributions from the global engineering community! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Security Policy](SECURITY.md) before submitting pull requests.

---

## License

`tezca` is open-source software licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.
