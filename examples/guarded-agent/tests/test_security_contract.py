"""Offline end-to-end checks for the guarded-agent security boundary."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

EXAMPLE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = EXAMPLE_ROOT.parents[1]
sys.path.insert(0, str(EXAMPLE_ROOT))

from app.approver import DevelopmentApprover
from app.guard import DemoGuardRuntime
from app.offline import OfflineSecurityScenario
from app.tools import RecordStore


def guard_binary() -> Path:
    if configured := os.environ.get("ARMORER_GUARD_BIN"):
        return Path(configured).expanduser().resolve()
    built = REPOSITORY_ROOT / "target" / "release" / "armorer-guard"
    if built.is_file():
        return built
    if installed := shutil.which("armorer-guard"):
        return Path(installed)
    raise RuntimeError("build Guard first with `cargo build --release`")


def load_fixtures() -> dict[str, dict[str, Any]]:
    return {
        path.stem.replace("-", "_"): json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((EXAMPLE_ROOT / "fixtures").glob("*.json"))
    }


class GuardedAgentSecurityContractTest(unittest.TestCase):
    def test_record_store_supports_agent_discovery_and_search(self) -> None:
        with tempfile.TemporaryDirectory(prefix="armorer-record-store-") as temporary:
            records = RecordStore(Path(temporary))
            records.create("record/123", "Duplicate of record/456")
            records.create("record/456", "Canonical customer record")

            self.assertEqual(records.list_records(), ["record/123", "record/456"])
            self.assertEqual(records.read("record/456"), "Canonical customer record")
            self.assertEqual(
                records.search("duplicate"),
                [
                    {
                        "record_id": "record/123",
                        "snippet": "Duplicate of record/456",
                    }
                ],
            )
            self.assertIsNone(records.read("record/missing"))

    def test_complete_security_flow_without_an_api_call(self) -> None:
        fixtures = load_fixtures()
        with tempfile.TemporaryDirectory(prefix="armorer-guard-test-") as temporary:
            root = Path(temporary)
            records = RecordStore(root / "records")
            records.create("record/123", "temporary demo record\n")
            with DemoGuardRuntime(
                guard_binary(), EXAMPLE_ROOT, root / "guard-runtime"
            ) as guard:
                result = OfflineSecurityScenario(
                    guard, DevelopmentApprover(guard.approval_key), records
                ).run(fixtures)

        self.assertEqual(result["readiness"]["status"], "ready")
        self.assertEqual(result["safe_content"]["effect"], "allow_untrusted_data")
        self.assertEqual(result["hostile_content"]["effect"], "quarantine")
        self.assertEqual(result["cross_tenant_denial"]["effect"], "deny")
        self.assertFalse(result["cross_tenant_denial"]["downstream_dispatched"])
        self.assertEqual(result["approval_required"]["effect"], "require_approval")
        self.assertEqual(result["approved_action"]["effect"], "allow")
        self.assertTrue(result["execution"]["authorized"])
        self.assertTrue(result["execution"]["temporary_record_removed"])
        self.assertEqual(result["execution"]["downstream_outcome"], "succeeded")
        self.assertTrue(result["token_replay"]["rejected"])

    def test_human_delay_does_not_change_approval_binding(self) -> None:
        fixture = load_fixtures()["delete_action"]
        with tempfile.TemporaryDirectory(prefix="approval-") as temporary:
            root = Path(temporary)
            with DemoGuardRuntime(
                guard_binary(), EXAMPLE_ROOT, root / "guard-runtime"
            ) as guard:
                request = guard.authority_request(fixture)
                request["context"]["observed_at"] = int(time.time()) - 10
                initial = guard.guard.action(request)
                self.assertEqual(initial["effect"], "require_approval")

                approver = DevelopmentApprover(guard.approval_key)
                challenge = guard.create_approval_challenge(
                    request, fixture["required_approval_role"]
                )
                receipt = approver.approve(challenge, fixture["required_approval_role"])
                guard.consume_approval(request, receipt)
                approved_request = guard.attach_approval(request, receipt)

                self.assertEqual(
                    approved_request["context"]["observed_at"],
                    request["context"]["observed_at"],
                )
                self.assertEqual(
                    guard.guard.action(approved_request)["effect"], "allow"
                )


if __name__ == "__main__":
    unittest.main()
