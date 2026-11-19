"""
LangChain and LangGraph callback handler for automated tezca audit logging.
"""

from __future__ import annotations

from typing import Any, Optional

from tezca.events import AgentEventType
from tezca.ledger import Ledger

# Opportunistically inherit from langchain_core if installed; otherwise fallback to base object
try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    class BaseCallbackHandler:  # type: ignore
        pass


class TezcaCallbackHandler(BaseCallbackHandler):
    """
    Automated callback handler for LangChain and LangGraph runnables.
    Intercepts LLM prompts, completions, tool invocations, and chain executions.
    """

    def __init__(
        self,
        ledger: Ledger,
        agent_id: str = "langchain-agent",
        session_id: Optional[str] = None,
    ):
        self.ledger = ledger
        self.agent_id = agent_id
        self.session_id = session_id

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Record incoming LLM prompt."""
        self.ledger.record(
            agent_id=self.agent_id,
            event_type=AgentEventType.PROMPT.value,
            data={"prompts": prompts, "serialized": serialized},
            metadata={"session_id": self.session_id, **kwargs.get("metadata", {})},
        )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Record LLM generation output."""
        generations = getattr(response, "generations", [])
        output_text = [
            gen.text for sublist in generations for gen in sublist if hasattr(gen, "text")
        ]
        llm_output = getattr(response, "llm_output", {}) or {}

        self.ledger.record(
            agent_id=self.agent_id,
            event_type=AgentEventType.COMPLETION.value,
            data={"output_text": output_text, "llm_output": llm_output},
            metadata={"session_id": self.session_id, **kwargs.get("metadata", {})},
        )

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        """Record LLM execution exception."""
        self.ledger.record(
            agent_id=self.agent_id,
            event_type=AgentEventType.ERROR.value,
            data={"error_type": type(error).__name__, "error_message": str(error)},
            metadata={"session_id": self.session_id, "scope": "llm"},
        )

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Record tool call invocation."""
        name = serialized.get("name", "unknown_tool") if isinstance(serialized, dict) else "unknown_tool"
        self.ledger.record(
            agent_id=self.agent_id,
            event_type=AgentEventType.TOOL_CALL.value,
            data={"tool_name": name, "input": input_str},
            metadata={"session_id": self.session_id},
        )

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        """Record tool execution result."""
        self.ledger.record(
            agent_id=self.agent_id,
            event_type=AgentEventType.TOOL_RESULT.value,
            data={"output": str(output)},
            metadata={"session_id": self.session_id},
        )

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        """Record tool execution error."""
        self.ledger.record(
            agent_id=self.agent_id,
            event_type=AgentEventType.ERROR.value,
            data={"error_type": type(error).__name__, "error_message": str(error)},
            metadata={"session_id": self.session_id, "scope": "tool"},
        )

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Record chain or graph execution start."""
        chain_name = serialized.get("name", "chain") if isinstance(serialized, dict) else "chain"
        self.ledger.record(
            agent_id=self.agent_id,
            event_type=AgentEventType.AGENT_THOUGHT.value,
            data={"chain_name": chain_name, "inputs": inputs},
            metadata={"session_id": self.session_id, "phase": "chain_start"},
        )

    def on_chain_end(self, outputs: dict[str, Any], **kwargs: Any) -> None:
        """Record chain or graph execution conclusion."""
        self.ledger.record(
            agent_id=self.agent_id,
            event_type=AgentEventType.DELEGATION.value,
            data={"outputs": outputs},
            metadata={"session_id": self.session_id, "phase": "chain_end"},
        )
