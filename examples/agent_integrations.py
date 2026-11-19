"""
Demonstration of agent framework integrations: LangChain callbacks, tool decorators, and SDK wrappers.
"""

import sys
from pathlib import Path
from types import SimpleNamespace

# Allow direct execution from repository root without prior pip install
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from tezca import (
    AgentEvent,
    AgentEventType,
    Ledger,
    TezcaCallbackHandler,
    track_agent_call,
    wrap_completion,
    wrap_tool,
)


def run_integrations_demo():
    db_file = Path("integrations_demo.db")
    if db_file.exists():
        db_file.unlink()

    with Ledger(db_file) as ledger:
        print("1. Recording standardized AgentEvents...")
        ledger.record_event(
            AgentEvent(
                agent_id="remedy-bot",
                event_type=AgentEventType.GUARDRAIL_VERDICT,
                data={"rule": "pii_sanitization", "status": "APPROVED"},
                session_id="sess_777",
            )
        )

        print("\n2. Decorating an agent tool with @wrap_tool...")
        @wrap_tool(ledger, agent_id="remedy-bot", tool_name="fetch_patient_vitals")
        def fetch_vitals(patient_id: str):
            return {"heart_rate": 72, "spo2": 98, "temp_c": 36.6}

        vitals = fetch_vitals("pat_1092")
        print("Tool returned vitals:", vitals)

        print("\n3. Wrapping an LLM call with @wrap_completion...")
        @wrap_completion(ledger, agent_id="remedy-bot", model="gpt-4o")
        def mock_llm_call(prompt: str):
            return SimpleNamespace(
                text="Patient vitals are within normal range.",
                usage={"prompt_tokens": 40, "completion_tokens": 12},
            )

        resp = mock_llm_call("Summarize patient health.")
        print("LLM generated output:", resp.text)

        print("\n4. Tracing a multi-step block with track_agent_call context manager...")
        with track_agent_call(ledger, agent_id="remedy-bot", event_type="diagnosis_pipeline") as ctx:
            ctx["decision"] = "DISCHARGE"
            ctx["confidence"] = 0.99

        print("\n5. Using TezcaCallbackHandler (LangChain / LangGraph)...")
        handler = TezcaCallbackHandler(ledger, agent_id="langchain-bot", session_id="sess_888")
        handler.on_tool_start({"name": "send_email"}, "user@hospital.org")
        handler.on_tool_end("Email dispatched successfully.")

        valid, report = ledger.verify()
        print(f"\n[OK] Ledger verification: {report['verified_events']} events sealed in cryptographic chain.")
        print(f"[OK] Chain valid: {valid}")

    if db_file.exists():
        db_file.unlink()


if __name__ == "__main__":
    run_integrations_demo()
