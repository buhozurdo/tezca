"""
Zero-dependency interceptors and decorators for OpenAI, Anthropic, and custom agent tools.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import time
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional

from tezca.events import AgentEventType
from tezca.ledger import Ledger


def wrap_tool(
    ledger: Ledger,
    agent_id: str = "tool-runner",
    tool_name: Optional[str] = None,
) -> Callable:
    """
    Decorator for Python tool functions and agent actions.
    Automatically captures arguments, execution latency, and return values/exceptions.
    Supports both synchronous and asynchronous functions.
    """

    def decorator(fn: Callable) -> Callable:
        name = tool_name or fn.__name__

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                bound_args = {"args": args, "kwargs": kwargs}
                ledger.record(
                    agent_id=agent_id,
                    event_type=AgentEventType.TOOL_CALL.value,
                    data={"tool": name, "arguments": bound_args},
                )
                start = time.perf_counter()
                try:
                    result = await fn(*args, **kwargs)
                    elapsed = (time.perf_counter() - start) * 1000.0
                    ledger.record(
                        agent_id=agent_id,
                        event_type=AgentEventType.TOOL_RESULT.value,
                        data={"tool": name, "result": result},
                        metadata={"latency_ms": round(elapsed, 2)},
                    )
                    return result
                except Exception as ex:
                    elapsed = (time.perf_counter() - start) * 1000.0
                    ledger.record(
                        agent_id=agent_id,
                        event_type=AgentEventType.ERROR.value,
                        data={"tool": name, "error_type": type(ex).__name__, "error": str(ex)},
                        metadata={"latency_ms": round(elapsed, 2)},
                    )
                    raise

            return async_wrapper

        else:

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                bound_args = {"args": args, "kwargs": kwargs}
                ledger.record(
                    agent_id=agent_id,
                    event_type=AgentEventType.TOOL_CALL.value,
                    data={"tool": name, "arguments": bound_args},
                )
                start = time.perf_counter()
                try:
                    result = fn(*args, **kwargs)
                    elapsed = (time.perf_counter() - start) * 1000.0
                    ledger.record(
                        agent_id=agent_id,
                        event_type=AgentEventType.TOOL_RESULT.value,
                        data={"tool": name, "result": result},
                        metadata={"latency_ms": round(elapsed, 2)},
                    )
                    return result
                except Exception as ex:
                    elapsed = (time.perf_counter() - start) * 1000.0
                    ledger.record(
                        agent_id=agent_id,
                        event_type=AgentEventType.ERROR.value,
                        data={"tool": name, "error_type": type(ex).__name__, "error": str(ex)},
                        metadata={"latency_ms": round(elapsed, 2)},
                    )
                    raise

            return sync_wrapper

    return decorator


def wrap_completion(
    ledger: Ledger,
    agent_id: str = "llm-agent",
    model: Optional[str] = None,
) -> Callable:
    """
    Decorator for OpenAI, Anthropic, or custom LLM client completion functions.
    Extracts prompts, generated responses, token usage, and latency.
    """

    def decorator(fn: Callable) -> Callable:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                messages = kwargs.get("messages") or kwargs.get("prompt") or args
                used_model = kwargs.get("model") or model or "unknown"
                ledger.record(
                    agent_id=agent_id,
                    event_type=AgentEventType.PROMPT.value,
                    data={"messages": messages, "model": used_model},
                )
                start = time.perf_counter()
                try:
                    response = await fn(*args, **kwargs)
                    elapsed = (time.perf_counter() - start) * 1000.0
                    usage = getattr(response, "usage", None)
                    usage_dict = usage if isinstance(usage, dict) else (usage.__dict__ if hasattr(usage, "__dict__") else None)

                    ledger.record(
                        agent_id=agent_id,
                        event_type=AgentEventType.COMPLETION.value,
                        data={"response": str(response)},
                        metadata={
                            "model": used_model,
                            "latency_ms": round(elapsed, 2),
                            "token_usage": usage_dict,
                        },
                    )
                    return response
                except Exception as ex:
                    elapsed = (time.perf_counter() - start) * 1000.0
                    ledger.record(
                        agent_id=agent_id,
                        event_type=AgentEventType.ERROR.value,
                        data={"error_type": type(ex).__name__, "error": str(ex)},
                        metadata={"model": used_model, "latency_ms": round(elapsed, 2)},
                    )
                    raise

            return async_wrapper

        else:

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                messages = kwargs.get("messages") or kwargs.get("prompt") or args
                used_model = kwargs.get("model") or model or "unknown"
                ledger.record(
                    agent_id=agent_id,
                    event_type=AgentEventType.PROMPT.value,
                    data={"messages": messages, "model": used_model},
                )
                start = time.perf_counter()
                try:
                    response = fn(*args, **kwargs)
                    elapsed = (time.perf_counter() - start) * 1000.0
                    usage = getattr(response, "usage", None)
                    usage_dict = usage if isinstance(usage, dict) else (usage.__dict__ if hasattr(usage, "__dict__") else None)

                    ledger.record(
                        agent_id=agent_id,
                        event_type=AgentEventType.COMPLETION.value,
                        data={"response": str(response)},
                        metadata={
                            "model": used_model,
                            "latency_ms": round(elapsed, 2),
                            "token_usage": usage_dict,
                        },
                    )
                    return response
                except Exception as ex:
                    elapsed = (time.perf_counter() - start) * 1000.0
                    ledger.record(
                        agent_id=agent_id,
                        event_type=AgentEventType.ERROR.value,
                        data={"error_type": type(ex).__name__, "error": str(ex)},
                        metadata={"model": used_model, "latency_ms": round(elapsed, 2)},
                    )
                    raise

            return sync_wrapper

    return decorator


@contextmanager
def track_agent_call(
    ledger: Ledger,
    agent_id: str,
    event_type: str = "action",
    data: Optional[dict[str, Any]] = None,
) -> Iterator[dict[str, Any]]:
    """
    Context manager to trace and seal an arbitrary block of agent logic.
    Yields a mutable context dict where extra metadata can be attached.
    """
    ctx: dict[str, Any] = {}
    payload = data if data is not None else {}
    start = time.perf_counter()
    try:
        yield ctx
        elapsed = (time.perf_counter() - start) * 1000.0
        ledger.record(
            agent_id=agent_id,
            event_type=event_type,
            data=payload,
            metadata={"latency_ms": round(elapsed, 2), **ctx},
        )
    except Exception as ex:
        elapsed = (time.perf_counter() - start) * 1000.0
        ledger.record(
            agent_id=agent_id,
            event_type=AgentEventType.ERROR.value,
            data={"error_type": type(ex).__name__, "error": str(ex), **payload},
            metadata={"latency_ms": round(elapsed, 2), **ctx},
        )
        raise
