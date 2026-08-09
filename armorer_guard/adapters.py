"""Framework convenience adapters over the Guard sidecar security boundary.

These adapters intentionally contain no policy or detection logic. They only
preserve the versioned envelopes, suspension behavior, and execution receipts.
"""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable

from . import GuardDenied, GuardSidecar, protect_capability


class OpenAICompatibleAdapter:
    def __init__(self, guard: GuardSidecar) -> None:
        self.guard = guard

    async def invoke(
        self,
        request_envelope: dict[str, Any],
        call: Callable[[], Any | Awaitable[Any]],
        response_envelope: Callable[[Any], dict[str, Any] | Awaitable[dict[str, Any]]],
    ) -> Any:
        request_decision = self.guard.model_request(request_envelope)
        if request_decision.get("effect") in {"deny", "quarantine", "require_approval"}:
            raise GuardDenied("Guard rejected the model request", decision=request_decision)
        result = call()
        if inspect.isawaitable(result):
            result = await result
        response = response_envelope(result)
        if inspect.isawaitable(response):
            response = await response
        response_decision = self.guard.model_response(response)
        if response_decision.get("effect") in {"deny", "quarantine", "require_approval"}:
            raise GuardDenied("Guard rejected the model response", decision=response_decision)
        return result


class OpenAIAgentsAdapter(OpenAICompatibleAdapter):
    """Hooks for model calls and function tools in the OpenAI Agents SDK."""

    def tool(self, authority_request: Callable[..., dict[str, Any]]):
        return protect_capability(self.guard, authority_request)


class LangGraphAdapter(OpenAICompatibleAdapter):
    """LangGraph/LangChain model middleware and tool decorator."""

    def tool(self, authority_request: Callable[..., dict[str, Any]]):
        return protect_capability(self.guard, authority_request)

    def supervise_tool_result(self, envelope: dict[str, Any]) -> dict[str, Any]:
        decision = self.guard.tool_result(envelope)
        if decision.get("effect") in {"deny", "quarantine", "require_approval"}:
            raise GuardDenied("Guard rejected the tool result", decision=decision)
        return decision

    def supervise_memory_write(self, envelope: dict[str, Any]) -> dict[str, Any]:
        decision = self.guard.memory_write(envelope)
        if decision.get("effect") in {"deny", "quarantine", "require_approval"}:
            raise GuardDenied("Guard rejected the memory write", decision=decision)
        return decision

    def supervise_memory_read(self, envelope: dict[str, Any]) -> dict[str, Any]:
        decision = self.guard.memory_read(envelope)
        if decision.get("effect") in {"deny", "quarantine", "require_approval"}:
            raise GuardDenied("Guard rejected the memory read", decision=decision)
        return decision


class CrewAIAdapter(LangGraphAdapter):
    """CrewAI task/model supervision and guarded tool decorator."""


class HttpWebhookAdapter:
    def __init__(self, guard: GuardSidecar) -> None:
        self.guard = guard

    def ingress(self, envelope: dict[str, Any]) -> dict[str, Any]:
        decision = self.guard.input(envelope)
        if decision.get("effect") in {"deny", "quarantine", "require_approval"}:
            raise GuardDenied("Guard rejected HTTP ingress", decision=decision)
        return decision

    def egress(self, envelope: dict[str, Any]) -> dict[str, Any]:
        decision = self.guard.output(envelope)
        if decision.get("effect") in {"deny", "quarantine", "require_approval"}:
            raise GuardDenied("Guard rejected HTTP egress", decision=decision)
        return decision


class InterAgentAdapter:
    def __init__(self, guard: GuardSidecar) -> None:
        self.guard = guard

    def send_or_receive(self, envelope: dict[str, Any]) -> dict[str, Any]:
        decision = self.guard.inter_agent(envelope)
        if decision.get("effect") in {"deny", "quarantine", "require_approval"}:
            raise GuardDenied("Guard rejected inter-agent content", decision=decision)
        return decision
