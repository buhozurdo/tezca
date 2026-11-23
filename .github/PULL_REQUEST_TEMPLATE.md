## Description
Provide a concise summary of the changes introduced in this pull request and the rationale behind them.

Closes # (issue number if applicable)

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Performance optimization (latency/memory improvement)
- [ ] Documentation update
- [ ] Refactoring (no functional changes)

## Quality Checklist
- [ ] Follows the **Zero Runtime Dependency** rule (uses only Python Standard Library).
- [ ] Code is documented in English (docstrings, comments).
- [ ] Tests added/updated covering all modified execution paths.
- [ ] Passes all test suites: `python -m pytest tests/`
- [ ] Coverage maintained at $\ge 95\%$ (run: `pytest --cov=tezca --cov-report=term-missing`).
- [ ] Type hints verified and compliant with PEP 561.
- [ ] No duplicate blocks flagged by CPD.
