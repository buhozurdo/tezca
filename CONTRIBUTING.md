# Contributing to tezca

Thank you for your interest in contributing to `tezca`! We welcome contributions from engineers, researchers, and security practitioners across the global AI ecosystem.

`tezca` is engineered to enterprise-grade standards. To ensure safety, cryptographic determinism, and zero-friction adoption by tier-1 organizations, all contributions must adhere to the principles outlined below.

---

## Core Engineering Principles

1. **Zero Runtime Dependencies:**
   `tezca` will **never** add third-party runtime dependencies. All core primitives (cryptography, serialization, storage, CLI) must rely exclusively on the Python Standard Library (`hashlib`, `hmac`, `json`, `sqlite3`, `dataclasses`, `datetime`, `argparse`). Opportunistic performance extensions (e.g., `orjson`) are acceptable only if standard library fallback is preserved and 100% functional.
2. **Cryptographic Invariance & Determinism:**
   Hash calculation and canonical serialization must be completely deterministic across operating systems (Linux, macOS, Windows) and Python versions (3.9 through 3.14+).
3. **Strict Static Typing:**
   Every function, method, and public interface must include comprehensive PEP 484 type annotations compatible with `mypy` and `pyright` under strict settings.
4. **100% Test Coverage & Zero Code Duplication:**
   Every new feature or bugfix must be accompanied by comprehensive unit tests. Pull requests dropping overall statement coverage below 95% will not pass CI.

---

## Development Setup

### 1. Clone & Environment
```bash
git clone https://github.com/buhozurdo/tezca.git
cd tezca

# Create a clean virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 2. Install Development Dependencies
Development tooling (testing, coverage, linting) is kept strictly isolated from package dependencies:
```bash
pip install pytest pytest-cov coverage
```

### 3. Running the Test Suite
Ensure all existing tests pass with full coverage:
```bash
# Run unit tests
python -m pytest tests/

# Run with full branch coverage report
python -m pytest tests/ --cov=tezca --cov-report=term-missing
```

---

## Git Workflow & Branching Strategy

We follow a modified Gitflow / Release Train workflow:

```
[ feature/* ] ────────▶ [ dev ] ────────▶ [ release/vX.Y.0 ] ────────▶ [ main ]
(Feature branch)        (Integration)     (Stabilization)              (Production GA)
```

1. **Branch off `dev`:** Never branch feature work from `main`. Always create branches from the latest `dev`:
   ```bash
   git checkout dev
   git pull origin dev
   git checkout -b feature/your-feature-name
   ```
2. **Conventional Commits:** Commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
   - `feat(scope): add feature description`
   - `fix(scope): resolve issue description`
   - `perf(scope): optimize latency or memory`
   - `test(scope): add or improve test coverage`
   - `docs(scope): update documentation or examples`
   - `refactor(scope): code cleanup without functional changes`

---

## Pull Request Checklist

Before submitting a Pull Request, verify:

- [ ] All code is strictly documented in English (docstrings, comments, commit messages).
- [ ] No third-party packages added to `dependencies` in `pyproject.toml`.
- [ ] Code passes all unit tests (`pytest`).
- [ ] Statement test coverage remains $\ge 95\%$ (preferably 100%).
- [ ] No duplicated blocks of code flagged by Copy/Paste Detector (CPD).
- [ ] Type hints are complete and verified with PEP 561 compliance.
- [ ] Examples and documentation updated where applicable.

---

## Code of Conduct

Contributors are expected to adhere to the Contributor Covenant v2.1. Please maintain professional, respectful, and collaborative communication at all times.
