"""Development-only approval signer for the guarded-agent example."""

from __future__ import annotations

import hashlib
import json
import time
from copy import deepcopy
from typing import Any, Protocol

from armorer_guard import canonical_json, sign_canonical


class ApprovalProvider(Protocol):
    def approve(
        self, challenge: dict[str, Any], required_role: str
    ) -> dict[str, Any] | None: ...


class ApprovalPresenter(Protocol):
    def confirm_approval(
        self, challenge: dict[str, Any], required_role: str
    ) -> bool: ...


class DevelopmentApprover:
    """Simulate an external human-approval service with its own key."""

    def __init__(self, signing_key: bytes) -> None:
        self.signing_key = signing_key

    def approve(self, challenge: dict[str, Any], required_role: str) -> dict[str, Any]:
        approved_at = int(time.time())
        receipt = {
            "schema_version": "armorer-guard-approval-receipt/v1",
            "receipt_id": "",
            "challenge": challenge,
            "approver_id": "user/demo-owner",
            "approver_role": required_role,
            "approved_at": approved_at,
            "expires_at": min(approved_at + 120, challenge["expires_at"]),
            "maximum_usage_count": 1,
            "signature": "",
        }
        identity = deepcopy(receipt)
        encoded = canonical_json(identity).encode()
        receipt["receipt_id"] = (
            "approval-receipt/sha256:" + hashlib.sha256(encoded).hexdigest()
        )
        receipt["signature"] = sign_canonical(self.signing_key, receipt)
        return receipt


class ConsoleApprover:
    """Ask a human before delegating signing to the demo approval service."""

    def __init__(
        self,
        signer: DevelopmentApprover,
        presenter: ApprovalPresenter | None = None,
    ) -> None:
        self.signer = signer
        self.presenter = presenter

    def approve(
        self, challenge: dict[str, Any], required_role: str
    ) -> dict[str, Any] | None:
        if self.presenter is not None:
            approved = self.presenter.confirm_approval(challenge, required_role)
        else:
            presentation = challenge["presentation"]
            print("\nGuard requires approval for this exact action:")
            print(
                json.dumps(
                    {
                        "capability_id": challenge["capability_id"],
                        "resource_id": challenge["resource_id"],
                        "required_role": required_role,
                        "arguments": presentation["normalized_arguments"],
                        "risk_score": presentation["risk_score"],
                        "irreversible": presentation["irreversible"],
                        "warnings": presentation["warnings"],
                    },
                    indent=2,
                )
            )
            approved = input("Approve this one action? [y/N]: ").strip().lower() in {
                "y",
                "yes",
            }
        if not approved:
            return None
        return self.signer.approve(challenge, required_role)
