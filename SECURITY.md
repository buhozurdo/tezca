# Security Policy

The `tezca` project takes security, cryptographic integrity, and forensic validity seriously. As an enterprise audit ledger designed for autonomous AI systems operating in regulated environments, we adhere to strict standards of code safety, threat modeling, and coordinated vulnerability disclosure.

---

## Supported Versions

Only the latest active minor release receives official security patches. Users are strongly advised to keep their deployments up to date.

| Version | Supported          | Security Maintenance Status |
| ------- | ------------------ | --------------------------- |
| `0.3.x` | :white_check_mark: | Active                      |
| `0.2.x` | :x:                | Deprecated                  |
| `0.1.x` | :x:                | Deprecated                  |

---

## Threat Model & Security Boundaries

`tezca` provides mathematical, tamper-evident audit logging and non-repudiation guarantees for autonomous AI agents. Understanding our threat boundary is critical for security architects:

### What Tezca Guarantees (In Scope)
1. **Cryptographic Tamper-Evidence:** Any retroactive alteration, deletion, or reordering of receipts breaks the SHA-256 hash chain and invalidates Merkle tree proofs.
2. **Author Non-Repudiation:** Optional HMAC-SHA256 signatures ensure that records cannot be forged without possession of the shared secret key.
3. **Canonical Determinism:** Canonical JSON serialization guarantees identical hash generation across disparate platforms, architectures, and Python versions.
4. **Zero Supply-Chain Attack Surface:** `tezca` requires **zero third-party runtime dependencies**. All cryptographic and storage operations execute exclusively through the Python Standard Library (`hashlib`, `hmac`, `sqlite3`, `json`).
5. **Zero Outbound Telemetry:** No network connections, telemetry beacons, or external pings are ever initiated. Data remains strictly on the host.

### What Tezca Does Not Guarantee (Out of Scope)
1. **Host-Level Compromise:** If an attacker gains root or arbitrary memory execution permissions, they can intercept private keys in memory before sealing.
2. **LLM Hallucinations:** Tezca records agent actions with forensic fidelity; it does not filter or moderate LLM reasoning or prompt contents.
3. **Secret Key Storage:** Secure injection of `secret_key` (via KMS, HashiCorp Vault, or AWS Secrets Manager) remains the responsibility of the host application.

---

## Reporting a Vulnerability

If you discover a security vulnerability, cryptographic flaw, or potential integrity bypass, **please do not disclose it publicly** via GitHub Issues or discussions.

Instead, please report it privately:

1. **Email:** Send full technical details, proof-of-concept, and environment information to **`security@buhozurdo.com`** or contact project maintainers via GitHub Private Vulnerability Reporting.
2. **PGP/Encrypted Communication:** If required, request maintainer PGP keys before transmitting sensitive proof-of-concept exploits.

### Incident Response Timeline (SLA)
- **Initial Acknowledgment:** Within **24 to 48 hours**.
- **Severity Assessment & Triaging:** Within **72 hours** (CVSS v3.1 scoring).
- **Remediation & Patch Target:** Within **14 business days** depending on severity.
- **Coordinated Public Disclosure:** Following advisory release and downstream notification.

---

## Security Best Practices for Production Deployments

When deploying `tezca` in enterprise pipelines:
1. **Mount with Write-Append Permissions:** Configure storage volumes (SQLite WAL or JSONL) with append-only access controls where possible.
2. **Harden Secret Key Handling:** Pass `secret_key` as raw bytes from an environment variable or secure memory vault; never hardcode credentials in code.
3. **Conduct Regular Audits:** Integrate `tezca verify` or scheduled CI verification jobs to routinely validate chain integrity.
