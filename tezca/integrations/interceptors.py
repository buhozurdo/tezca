"""
Zero-dependency interceptors and decorators for OpenAI, Anthropic, and custom agent tools.
"""

from __future__ import annotations

import functools
import inspect
import random
import time
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional

from tezca.events import AgentEventType
from tezca.ledger import Ledger


def _log_tool_invocation(ledger: Ledger, agent_id: str, tool_name: str, args: Any, kwargs: Any) -> None:
    ledger.record(
        agent_id=agent_id,
        event_type=AgentEventType.TOOL_CALL.value,
        data={"tool": tool_name, "arguments": {"args": args, "kwargs": kwargs}},
    )


def _log_tool_success(ledger: Ledger, agent_id: str, tool_name: str, result: Any, elapsed_ms: float) -> None:
    ledger.record(
        agent_id=agent_id,
        event_type=AgentEventType.TOOL_RESULT.value,
        data={"tool": tool_name, "result": result},
        metadata={"latency_ms": round(elapsed_ms, 2)},
    )


def _log_tool_failure(ledger: Ledger, agent_id: str, tool_name: str, ex: Exception, elapsed_ms: float) -> None:
    ledger.record(
        agent_id=agent_id,
        event_type=AgentEventType.ERROR.value,
        data={"tool": tool_name, "error_type": type(ex).__name__, "error": str(ex)},
        metadata={"latency_ms": round(elapsed_ms, 2)},
    )


def wrap_tool(
    ledger: Ledger,
    agent_id: str = "tool-runner",
    tool_name: Optional[str] = None,
    log_invocation: bool = True,
    sample_rate: float = 1.0,
) -> Callable:
    """
    Decorator for Python tool functions and agent actions.
    Automatically captures arguments, execution latency, and return values/exceptions.
    Supports both synchronous and asynchronous functions.
    Allows disabling tool_call invocation logging (recording only tool_result) and configurable sampling.
    """

    def decorator(fn: Callable) -> Callable:
        name = tool_name or fn.__name__

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                if sample_rate < 1.0 and random.random() >= sample_rate:
                    return await fn(*args, **kwargs)
                if log_invocation:
                    _log_tool_invocation(ledger, agent_id, name, args, kwargs)
                start = time.perf_counter()
                try:
                    res = await fn(*args, **kwargs)
                    _log_tool_success(ledger, agent_id, name, res, (time.perf_counter() - start) * 1000.0)
                    return res
                except Exception as ex:
                    _log_tool_failure(ledger, agent_id, name, ex, (time.perf_counter() - start) * 1000.0)
                    raise

            return async_wrapper

        else:

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                if sample_rate < 1.0 and random.random() >= sample_rate:
                    return fn(*args, **kwargs)
                if log_invocation:
                    _log_tool_invocation(ledger, agent_id, name, args, kwargs)
                start = time.perf_counter()
                try:
                    res = fn(*args, **kwargs)
                    _log_tool_success(ledger, agent_id, name, res, (time.perf_counter() - start) * 1000.0)
                    return res
                except Exception as ex:
                    _log_tool_failure(ledger, agent_id, name, ex, (time.perf_counter() - start) * 1000.0)
                    raise

            return sync_wrapper

    return decorator


def _log_completion_prompt(ledger: Ledger, agent_id: str, default_model: Optional[str], args: Any, kwargs: Any) -> str:
    messages = kwargs.get("messages") or kwargs.get("prompt") or args
    model = kwargs.get("model") or default_model or "unknown"
    ledger.record(
        agent_id=agent_id,
        event_type=AgentEventType.PROMPT.value,
        data={"messages": messages, "model": model},
    )
    return str(model)


def _log_completion_success(
    ledger: Ledger, agent_id: str, response: Any, model: str, elapsed_ms: float
) -> None:
    usage = getattr(response, "usage", None)
    usage_dict = usage if isinstance(usage, dict) else (usage.__dict__ if hasattr(usage, "__dict__") else None)
    ledger.record(
        agent_id=agent_id,
        event_type=AgentEventType.COMPLETION.value,
        data={"response": str(response)},
        metadata={
            "model": model,
            "latency_ms": round(elapsed_ms, 2),
            "token_usage": usage_dict,
        },
    )


def _log_completion_failure(
    ledger: Ledger, agent_id: str, ex: Exception, model: str, elapsed_ms: float
) -> None:
    ledger.record(
        agent_id=agent_id,
        event_type=AgentEventType.ERROR.value,
        data={"error_type": type(ex).__name__, "error": str(ex)},
        metadata={"model": model, "latency_ms": round(elapsed_ms, 2)},
    )


def wrap_completion(
    ledger: Ledger,
    agent_id: str = "llm-agent",
    model: Optional[str] = None,
    log_prompt: bool = True,
    sample_rate: float = 1.0,
) -> Callable:
    """
    Decorator for OpenAI, Anthropic, or custom LLM client completion functions.
    Extracts prompts, generated responses, token usage, and latency.
    Allows disabling prompt logging (recording only completion output) and configurable sampling.
    """

    def decorator(fn: Callable) -> Callable:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                if sample_rate < 1.0 and random.random() >= sample_rate:
                    return await fn(*args, **kwargs)
                if log_prompt:
                    used_model = _log_completion_prompt(ledger, agent_id, model, args, kwargs)
                else:
                    used_model = str(kwargs.get("model") or model or "unknown")
                start = time.perf_counter()
                try:
                    resp = await fn(*args, **kwargs)
                    _log_completion_success(ledger, agent_id, resp, used_model, (time.perf_counter() - start) * 1000.0)
                    return resp
                except Exception as ex:
                    _log_completion_failure(ledger, agent_id, ex, used_model, (time.perf_counter() - start) * 1000.0)
                    raise

            return async_wrapper

        else:

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                if sample_rate < 1.0 and random.random() >= sample_rate:
                    return fn(*args, **kwargs)
                if log_prompt:
                    used_model = _log_completion_prompt(ledger, agent_id, model, args, kwargs)
                else:
                    used_model = str(kwargs.get("model") or model or "unknown")
                start = time.perf_counter()
                try:
                    resp = fn(*args, **kwargs)
                    _log_completion_success(ledger, agent_id, resp, used_model, (time.perf_counter() - start) * 1000.0)
                    return resp
                except Exception as ex:
                    _log_completion_failure(ledger, agent_id, ex, used_model, (time.perf_counter() - start) * 1000.0)
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
