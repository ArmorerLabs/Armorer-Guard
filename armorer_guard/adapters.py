"""Framework adapters that carry Guard decisions to protected boundaries."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from .client import GuardDenied, GuardSidecar, protect_capability

_ADMITTED_CONTENT_EFFECTS = {
    "allow",
    "allow_trusted_instruction",
    "allow_untrusted_data",
    "warn_and_allow",
    "redact_and_allow",
}


def _require_exact_content_admission(
    decision: dict[str, Any], envelope: dict[str, Any], boundary: str
) -> None:
    if decision.get("effect") not in _ADMITTED_CONTENT_EFFECTS:
        raise GuardDenied(f"Guard rejected the {boundary}", decision=decision)
    source_segments = envelope.get("segments")
    decided_segments = decision.get("segments")
    if not isinstance(source_segments, list) or not isinstance(decided_segments, list):
        raise GuardDenied(
            f"Guard returned an invalid {boundary} content decision",
            code="INVALID_CONTENT_DECISION",
            decision=decision,
        )
    originals: dict[Any, Any] = {}
    for segment in source_segments:
        if not isinstance(segment, dict) or "content_ref" not in segment:
            raise GuardDenied(
                f"The {boundary} envelope contains an invalid segment",
                code="INVALID_CONTENT_ENVELOPE",
                decision=decision,
            )
        originals[segment["content_ref"]] = segment.get("text")
    exact = len(originals) == len(source_segments) == len(decided_segments)
    decided_refs: set[Any] = set()
    if exact:
        for segment in decided_segments:
            if not isinstance(segment, dict):
                exact = False
                break
            content_ref = segment.get("content_ref")
            if not isinstance(content_ref, str) or content_ref in decided_refs:
                exact = False
                break
            decided_refs.add(content_ref)
            if content_ref not in originals or originals[content_ref] != segment.get(
                "sanitized_text"
            ):
                exact = False
                break
        exact = exact and len(decided_refs) == len(originals)
    if not exact:
        raise GuardDenied(
            f"Guard transformed {boundary} content that this generic adapter cannot safely reconstruct",
            code="CONTENT_TRANSFORM_UNSUPPORTED",
            decision=decision,
        )


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
        _require_exact_content_admission(
            request_decision, request_envelope, "model request"
        )
        result = call()
        if inspect.isawaitable(result):
            result = await result
        response = response_envelope(result)
        if inspect.isawaitable(response):
            response = await response
        response_decision = self.guard.model_response(response)
        _require_exact_content_admission(response_decision, response, "model response")
        return result


class OpenAIAgentsAdapter(OpenAICompatibleAdapter):
    def tool(self, authority_request: Callable[..., dict[str, Any]]):
        return protect_capability(self.guard, authority_request)


class LangGraphAdapter(OpenAICompatibleAdapter):
    def tool(self, authority_request: Callable[..., dict[str, Any]]):
        return protect_capability(self.guard, authority_request)

    def supervise_tool_result(self, envelope: dict[str, Any]) -> dict[str, Any]:
        decision = self.guard.tool_result(envelope)
        if decision.get("effect") not in _ADMITTED_CONTENT_EFFECTS:
            raise GuardDenied("Guard rejected the tool result", decision=decision)
        return decision


class CrewAIAdapter(LangGraphAdapter):
    pass


class HttpWebhookAdapter:
    def __init__(self, guard: GuardSidecar) -> None:
        self.guard = guard

    def ingress(self, envelope: dict[str, Any]) -> dict[str, Any]:
        decision = self.guard.input(envelope)
        if decision.get("effect") not in _ADMITTED_CONTENT_EFFECTS:
            raise GuardDenied("Guard rejected HTTP ingress", decision=decision)
        return decision

    def egress(self, envelope: dict[str, Any]) -> dict[str, Any]:
        decision = self.guard.output(envelope)
        if decision.get("effect") not in _ADMITTED_CONTENT_EFFECTS:
            raise GuardDenied("Guard rejected HTTP egress", decision=decision)
        return decision
