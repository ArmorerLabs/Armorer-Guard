"""Deterministic offline exercise of the guarded-agent security contract."""

from __future__ import annotations

from typing import Any

from armorer_guard import GuardSidecarError

from .approver import DevelopmentApprover
from .guard import DemoGuardRuntime
from .tools import RecordStore


class OfflineSecurityScenario:
    """Exercise Guard without an API call so CI can verify the full boundary."""

    def __init__(
        self,
        guard: DemoGuardRuntime,
        approver: DevelopmentApprover,
        records: RecordStore,
    ) -> None:
        self.guard = guard
        self.approver = approver
        self.records = records

    def run(self, fixtures: dict[str, dict[str, Any]]) -> dict[str, Any]:
        health = self.guard.guard.request("/v1/readiness", method="GET")
        safe = self.guard.guard.input(
            self.guard.content_request(fixtures["safe_message"])
        )
        self._require_effect(safe, "allow_untrusted_data")

        hostile = self.guard.guard.model_request(
            self.guard.content_request(
                fixtures["hostile_retrieval"], include_model_route=True
            )
        )
        self._require_effect(hostile, "quarantine")

        denied_request = self.guard.authority_request(fixtures["cross_tenant_action"])
        denied = self.guard.guard.action(denied_request)
        self._require_effect(denied, "deny")

        delete_fixture = fixtures["delete_action"]
        delete_request = self.guard.authority_request(delete_fixture)
        approval_required = self.guard.guard.action(delete_request)
        self._require_effect(approval_required, "require_approval")

        challenge = self.guard.create_approval_challenge(
            delete_request, delete_fixture["required_approval_role"]
        )
        approval = self.approver.approve(
            challenge, delete_fixture["required_approval_role"]
        )
        self.guard.consume_approval(delete_request, approval)
        approved_request = self.guard.attach_approval(delete_request, approval)
        approved = self.guard.guard.action(approved_request)
        self._require_effect(approved, "allow")
        token = approved["execution_token"]

        grant, execution_receipt, removed = self.guard.dispatch(
            token,
            lambda: self.records.delete(delete_fixture["resource_id"]),
        )
        try:
            self.guard.replay(token)
        except GuardSidecarError as error:
            replay = {"rejected": True, "reason": str(error), "code": error.code}
        else:
            raise RuntimeError("single-use execution token was accepted twice")

        return {
            "readiness": health,
            "safe_content": self._content_summary(safe),
            "hostile_content": self._content_summary(hostile),
            "cross_tenant_denial": {
                "effect": denied["effect"],
                "reasons": denied["reason_codes"],
                "downstream_dispatched": denied["execution_receipt"][
                    "downstream_dispatched"
                ],
                "receipt_id": denied["execution_receipt"]["receipt_id"],
            },
            "approval_required": {
                "effect": approval_required["effect"],
                "reasons": approval_required["reason_codes"],
            },
            "approved_action": {
                "effect": approved["effect"],
                "approval_receipt_id": approval["receipt_id"],
                "execution_token_id": token["token_id"],
            },
            "execution": {
                "authorized": grant["authorized"],
                "temporary_record_removed": removed,
                "downstream_dispatched": execution_receipt["downstream_dispatched"],
                "downstream_outcome": execution_receipt["downstream_outcome"],
                "receipt_id": execution_receipt["receipt_id"],
            },
            "token_replay": replay,
        }

    @staticmethod
    def _content_summary(decision: dict[str, Any]) -> dict[str, Any]:
        return {"effect": decision["effect"], "reasons": decision["reason_codes"]}

    @staticmethod
    def _require_effect(decision: dict[str, Any], expected: str) -> None:
        if decision.get("effect") != expected:
            raise RuntimeError(
                f"expected Guard effect {expected!r}, got {decision.get('effect')!r}"
            )
