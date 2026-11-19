"""
Tests for LangChain callback handler and SDK interceptors (OpenAI / Anthropic / custom tools).
"""

import asyncio
from types import SimpleNamespace
import tempfile
import unittest
from pathlib import Path

from tezca.events import AgentEventType
from tezca.integrations.interceptors import track_agent_call, wrap_completion, wrap_tool
from tezca.integrations.langchain import TezcaCallbackHandler
from tezca.ledger import Ledger


class TestIntegrations(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "integ_test.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_langchain_callback_handler_full_lifecycle(self):
        with Ledger(self.db_path) as ledger:
            handler = TezcaCallbackHandler(ledger, agent_id="support-bot", session_id="sess_abc")

            # 1. LLM lifecycle
            handler.on_llm_start({"name": "ChatOpenAI"}, ["Hello!"])
            mock_gen = SimpleNamespace(text="Hi there!")
            mock_resp = SimpleNamespace(generations=[[mock_gen]], llm_output={"token_usage": 15})
            handler.on_llm_end(mock_resp)

            # 2. LLM error
            handler.on_llm_error(RuntimeError("Rate limit reached"))

            # 3. Tool lifecycle
            handler.on_tool_start({"name": "calculator"}, "2 + 2")
            handler.on_tool_end("4")
            handler.on_tool_error(ValueError("Division by zero"))

            # 4. Chain lifecycle
            handler.on_chain_start({"name": "agent_graph"}, {"query": "test"})
            handler.on_chain_end({"final_answer": "success"})

            self.assertEqual(len(ledger), 8)
            valid, report = ledger.verify()
            self.assertTrue(valid)
            self.assertEqual(report["verified_events"], 8)

    def test_wrap_tool_sync_and_async(self):
        with Ledger(self.db_path) as ledger:
            # Sync tool
            @wrap_tool(ledger, agent_id="worker", tool_name="multiply")
            def multiply(a: int, b: int) -> int:
                return a * b

            res = multiply(6, 7)
            self.assertEqual(res, 42)

            # Sync tool exception
            @wrap_tool(ledger, agent_id="worker", tool_name="failing_tool")
            def failing_tool():
                raise RuntimeError("Failed execution")

            with self.assertRaises(RuntimeError):
                failing_tool()

            # Async tool
            @wrap_tool(ledger, agent_id="worker", tool_name="async_add")
            async def async_add(a: int, b: int) -> int:
                return a + b

            async_res = asyncio.run(async_add(10, 20))
            self.assertEqual(async_res, 30)

            # Async tool exception
            @wrap_tool(ledger, agent_id="worker", tool_name="async_fail")
            async def async_fail():
                raise ValueError("Async error")

            with self.assertRaises(ValueError):
                asyncio.run(async_fail())

            self.assertEqual(len(ledger), 8)  # 2 events per invocation (start + result/error)
            self.assertTrue(ledger.verify()[0])

    def test_wrap_completion_sync_and_async(self):
        with Ledger(self.db_path) as ledger:
            # Sync completion with object usage
            @wrap_completion(ledger, agent_id="llm-caller", model="claude-3-5-sonnet")
            def fake_claude(prompt: str, **kwargs):
                return SimpleNamespace(content="Hello", usage=SimpleNamespace(input_tokens=5, output_tokens=10))

            resp = fake_claude("Hi")
            self.assertEqual(resp.content, "Hello")

            # Sync completion with failure
            @wrap_completion(ledger, agent_id="llm-caller")
            def fake_fail(prompt: str):
                raise ConnectionError("API unreachable")

            with self.assertRaises(ConnectionError):
                fake_fail("Hi")

            # Async completion with dict usage
            @wrap_completion(ledger, agent_id="llm-caller", model="gpt-4o")
            async def fake_openai(messages: list):
                return SimpleNamespace(text="Done", usage={"prompt_tokens": 12, "completion_tokens": 8})

            async_resp = asyncio.run(fake_openai([{"role": "user", "content": "ping"}]))
            self.assertEqual(async_resp.text, "Done")

            # Async completion with failure
            @wrap_completion(ledger, agent_id="llm-caller")
            async def fake_async_fail(messages: list):
                raise TimeoutError("LLM timeout")

            with self.assertRaises(TimeoutError):
                asyncio.run(fake_async_fail([{"role": "user", "content": "ping"}]))

            self.assertEqual(len(ledger), 8)
            self.assertTrue(ledger.verify()[0])

    def test_track_agent_call_context_manager(self):
        with Ledger(self.db_path) as ledger:
            # Success
            with track_agent_call(ledger, agent_id="supervisor", event_type="plan", data={"step": 1}) as ctx:
                ctx["custom_metric"] = 42
                result = 100

            # Failure
            with self.assertRaises(ZeroDivisionError):
                with track_agent_call(ledger, agent_id="supervisor", data={"attempt": "div_zero"}) as ctx:
                    ctx["status"] = "will_fail"
                    _ = 1 / 0

            self.assertEqual(len(ledger), 2)
            valid, report = ledger.verify()
            self.assertTrue(valid)
            self.assertEqual(report["verified_events"], 2)


if __name__ == "__main__":
    unittest.main()
