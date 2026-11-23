---
name: Integration Proposal (RFC)
about: Propose a new agent framework adapter (e.g., AutoGen, CrewAI, LiteLLM, LlamaIndex)
title: "[RFC] Integration: "
labels: ["integration", "rfc"]
assignees: ""
---

### Framework Target
Which AI / LLM orchestration framework are you proposing to support? (e.g., AutoGen, CrewAI, DSPy, Semantic Kernel, LiteLLM)

### Use Case
Describe how developers will use this adapter to capture tamper-evident audit receipts during agent execution.

### Proposed Code Example
```python
from tezca import Ledger
from tezca.integrations.your_integration import YourAdapter

# Example usage
```

### Dependency Strategy
How will this adapter handle imports if the target framework is not installed in the user's environment? (Must use opportunistic `try...except ImportError` fallback with zero required dependencies in `pyproject.toml`).
