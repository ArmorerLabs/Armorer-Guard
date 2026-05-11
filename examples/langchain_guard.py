"""LangChain-style boundary checks with Armorer Guard.

This file keeps imports light so you can copy the guard functions into any
LangChain app. Use `guard_retrieved_text` before adding untrusted retrieval
results to context and `guard_tool_args` before invoking tools.
"""

from __future__ import annotations

from typing import Any

import armorer_guard


BLOCK_REASONS = {
    "semantic:prompt_injection",
    "semantic:data_exfiltration",
    "semantic:system_prompt_extraction",
    "policy:credential_disclosure",
    "policy:dangerous_tool_call",
}


class GuardBlocked(RuntimeError):
    def __init__(self, reasons: list[str], confidence: float) -> None:
        super().__init__(f"Armorer Guard blocked content: {', '.join(reasons)}")
        self.reasons = reasons
        self.confidence = confidence


def _enforce(text: str, context: dict[str, Any]) -> str:
    verdict = armorer_guard.inspect_input(text, context=context)
    if verdict.suspicious and BLOCK_REASONS.intersection(verdict.reasons):
        raise GuardBlocked(verdict.reasons, verdict.confidence)
    return verdict.sanitized_text


def guard_retrieved_text(text: str, source: str = "retrieval") -> str:
    return _enforce(
        text,
        {
            "eval_surface": "retrieved_content",
            "trace_stage": "context_ingress",
            "artifact_kind": source,
        },
    )


def guard_tool_args(tool_name: str, args: str) -> str:
    return _enforce(
        args,
        {
            "eval_surface": "tool_call_args",
            "trace_stage": "action",
            "tool_name": tool_name,
        },
    )


if __name__ == "__main__":
    safe_context = guard_retrieved_text("The release notes say version 2.1 shipped today.")
    print(safe_context)
