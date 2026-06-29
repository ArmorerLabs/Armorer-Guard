"""OpenAI Agents SDK guard boundaries with Armorer Guard.

Use `guard_agent_context` before untrusted user or retrieval text reaches
`Runner.run`. Use `armorer_tool_input_guardrail` on function tools so proposed
tool-call arguments are inspected immediately before execution.

The local demo at the bottom does not call OpenAI and does not need real
secrets. If `openai-agents` is installed, `build_agent` shows the SDK wiring.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any

import armorer_guard

try:
    from agents import (
        Agent,
        Runner,
        ToolGuardrailFunctionOutput,
        function_tool,
        tool_input_guardrail,
    )
except ImportError:  # Keep the demo runnable with only armorer-guard installed.
    Agent = None
    Runner = None
    ToolGuardrailFunctionOutput = None
    function_tool = None
    tool_input_guardrail = None


BLOCK_REASONS = {
    "semantic:prompt_injection",
    "semantic:data_exfiltration",
    "semantic:system_prompt_extraction",
    "semantic:safety_bypass",
    "semantic:destructive_command",
    "policy:credential_disclosure",
    "policy:dangerous_tool_call",
}


@dataclass(frozen=True)
class GuardDecision:
    action: str
    sanitized_text: str
    suspicious: bool
    reasons: list[str]
    confidence: float


class GuardBlocked(RuntimeError):
    def __init__(self, boundary: str, decision: GuardDecision) -> None:
        super().__init__(
            f"Armorer Guard {decision.action} at {boundary}: "
            f"{decision.reasons} confidence={decision.confidence:.3f}"
        )
        self.boundary = boundary
        self.decision = decision


def _decision(verdict: armorer_guard.Inspection, original_text: str) -> GuardDecision:
    reasons = set(verdict.reasons)
    if BLOCK_REASONS.intersection(reasons):
        action = "block"
    elif verdict.suspicious and verdict.confidence >= 0.74:
        action = "escalate"
    elif verdict.sanitized_text != original_text:
        action = "redact"
    else:
        action = "allow"
    return GuardDecision(
        action=action,
        sanitized_text=verdict.sanitized_text,
        suspicious=verdict.suspicious,
        reasons=verdict.reasons,
        confidence=verdict.confidence,
    )


def inspect_agent_context(text: str, source: str = "user_input") -> GuardDecision:
    """Inspect user or retrieved text before it enters the agent context."""

    eval_surface = "retrieved_content" if source == "retrieval" else "user_input"
    verdict = armorer_guard.inspect_input(
        text,
        context={
            "eval_surface": eval_surface,
            "trace_stage": "context_ingress",
            "artifact_kind": source,
            "policy_scope": "openai_agents",
        },
    )
    return _decision(verdict, text)


def guard_agent_context(text: str, source: str = "user_input") -> str:
    decision = inspect_agent_context(text, source=source)
    if decision.action in {"block", "escalate"}:
        raise GuardBlocked(f"agent_context:{source}", decision)
    return decision.sanitized_text


def inspect_tool_args(tool_name: str, arguments: dict[str, Any]) -> GuardDecision:
    """Inspect proposed function-tool arguments before the tool executes."""

    payload = json.dumps(arguments, separators=(",", ":"), sort_keys=True)
    verdict = armorer_guard.inspect_input(
        payload,
        context={
            "eval_surface": "tool_call_args",
            "trace_stage": "action",
            "tool_name": tool_name,
            "policy_scope": "openai_agents",
        },
    )
    return _decision(verdict, payload)


def guard_tool_args(tool_name: str, arguments: dict[str, Any]) -> str:
    decision = inspect_tool_args(tool_name, arguments)
    if decision.action in {"block", "escalate"}:
        raise GuardBlocked(f"tool_call_args:{tool_name}", decision)
    return decision.sanitized_text


def _decode_sdk_tool_args(data: Any) -> dict[str, Any]:
    context = getattr(data, "context", None)
    raw_arguments = getattr(context, "tool_arguments", None) or "{}"
    try:
        decoded = json.loads(raw_arguments)
    except json.JSONDecodeError:
        return {"raw_tool_arguments": raw_arguments}
    if isinstance(decoded, dict):
        return decoded
    return {"tool_arguments": decoded}


create_release_note_tool = None

if (
    Agent is not None
    and Runner is not None
    and ToolGuardrailFunctionOutput is not None
    and function_tool is not None
    and tool_input_guardrail is not None
):

    @tool_input_guardrail
    def armorer_tool_input_guardrail(data: Any) -> Any:
        decision = inspect_tool_args("create_release_note", _decode_sdk_tool_args(data))
        if decision.action == "allow":
            return ToolGuardrailFunctionOutput.allow()
        if decision.action == "redact":
            return ToolGuardrailFunctionOutput.reject_content(
                json.dumps(
                    {
                        "action": "redact",
                        "sanitized_text": decision.sanitized_text,
                        "reasons": decision.reasons,
                        "confidence": decision.confidence,
                    },
                    separators=(",", ":"),
                )
            )
        return ToolGuardrailFunctionOutput.reject_content(
            json.dumps(asdict(decision), separators=(",", ":"))
        )

    @function_tool(tool_input_guardrails=[armorer_tool_input_guardrail])
    def create_release_note(title: str, body: str) -> str:
        """Draft a local release note from sanitized agent-provided text."""

        return f"{title}: {body[:120]}"

    create_release_note_tool = create_release_note


def build_agent() -> Any:
    """Return an Agents SDK agent wired with Armorer Guard tool guardrails."""

    if Agent is None or create_release_note_tool is None:
        raise RuntimeError("Install openai-agents to build the SDK agent.")
    return Agent(
        name="Guarded release-note assistant",
        instructions="Draft short release notes from user-approved inputs.",
        tools=[create_release_note_tool],
    )


async def run_agent_with_guard(user_text: str) -> Any:
    """Run an Agents SDK agent after a blocking local Armorer preflight."""

    if Runner is None:
        raise RuntimeError("Install openai-agents to run the SDK agent.")
    safe_text = guard_agent_context(user_text, source="user_input")
    return await Runner.run(build_agent(), safe_text)


def demo() -> None:
    benign_input = "Summarize the changelog entry for the local parser cleanup."
    benign_args = {"title": "Parser cleanup", "body": "Note the clearer error messages."}
    blocked_args = {"command": "rm -rf /", "reason": "clean old build artifacts"}

    print(json.dumps({"agent_input": asdict(inspect_agent_context(benign_input))}))
    print(
        json.dumps(
            {"tool_args": asdict(inspect_tool_args("create_release_note", benign_args))}
        )
    )
    try:
        guard_tool_args("Bash", blocked_args)
    except GuardBlocked as exc:
        print(
            json.dumps(
                {
                    "blocked_tool_call": True,
                    "boundary": exc.boundary,
                    "decision": asdict(exc.decision),
                }
            )
        )


if __name__ == "__main__":
    demo()
