"""
Standardized event schema and typed enumerations for AI agent audit logging.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional, Union


class AgentEventType(str, enum.Enum):
    """Canonical event types for AI agent forensic audit trails."""

    PROMPT = "prompt"
    COMPLETION = "completion"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    GUARDRAIL_VERDICT = "guardrail_verdict"
    AGENT_THOUGHT = "thought"
    DELEGATION = "delegation"
    ERROR = "error"
    CUSTOM = "custom"


@dataclass
class AgentEvent:
    """
    Standardized, high-level representation of an AI agent event.
    Provides structured schemas for LLM prompts, tool invocations, and guardrail verdicts.
    """

    agent_id: str
    event_type: Union[AgentEventType, str]
    data: dict[str, Any]
    session_id: Optional[str] = None
    model: Optional[str] = None
    token_usage: Optional[dict[str, int]] = None
    latency_ms: Optional[float] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_record_kwargs(self) -> dict[str, Any]:
        """Convert this event into Ledger.record() arguments."""
        ev_type = self.event_type.value if isinstance(self.event_type, AgentEventType) else str(self.event_type)
        combined_meta = dict(self.metadata)

        if self.session_id is not None:
            combined_meta["session_id"] = self.session_id
        if self.model is not None:
            combined_meta["model"] = self.model
        if self.token_usage is not None:
            combined_meta["token_usage"] = self.token_usage
        if self.latency_ms is not None:
            combined_meta["latency_ms"] = self.latency_ms

        return {
            "agent_id": self.agent_id,
            "event_type": ev_type,
            "data": self.data,
            "metadata": combined_meta,
        }
