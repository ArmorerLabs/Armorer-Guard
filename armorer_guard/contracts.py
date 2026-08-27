"""Typed Python views of the public Guard wire contract."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

TrustClass = Literal["platform", "trusted", "untrusted"]
InstructionAuthority = Literal["system", "developer", "user", "none"]
ContentEffect = Literal[
    "allow",
    "allow_trusted_instruction",
    "allow_untrusted_data",
    "warn_and_allow",
    "redact_and_allow",
    "quarantine",
    "require_approval",
    "deny",
]


class RuntimeSubject(TypedDict):
    agent_id: str
    identity_id: str
    tenant_id: str


class _ContentSegmentOptional(TypedDict, total=False):
    influenced_by: list[str]


class ContentSegment(_ContentSegmentOptional):
    content_ref: str
    origin: str
    principal_id: str
    tenant_id: str
    trust: TrustClass
    data_classes: list[str]
    instruction_authority: InstructionAuthority
    retention: str
    text: str


class _ContentEvaluationOptional(TypedDict, total=False):
    purpose: str | None
    allowed_context_origins: list[str]
    model_route: dict[str, Any] | None
    destination: dict[str, Any] | None
    memory_target: dict[str, str] | None


class ContentEvaluationRequest(_ContentEvaluationOptional):
    schema_version: Literal["armorer-guard-content-evaluation/v1"]
    request_id: str
    trace_id: str
    session_id: str
    subject: RuntimeSubject
    segments: list[ContentSegment]


class ContentFinding(TypedDict):
    reason_code: str
    lane: str
    category: str
    confidence: float
    disposition: Literal["observe", "review", "block"]


class _ContentDecisionOptional(TypedDict, total=False):
    content_review: dict[str, Any]


class ContentDecision(_ContentDecisionOptional):
    schema_version: Literal["armorer-guard-content-decision/v1"]
    decision_id: str
    request_id: str
    trace_id: str
    stage: str
    effect: ContentEffect
    reason_codes: list[str]
    segments: list[dict[str, Any]]


class AuthorityRequest(TypedDict):
    schema_version: Literal["armorer-guard-authority-request/v2"]
    request_id: str
    subject: dict[str, str]
    delegation: dict[str, Any]
    action: dict[str, Any]
    resource: dict[str, Any]
    influence: dict[str, Any]
    context: dict[str, Any]
