"""Guard-sidecar integration for the guarded-agent example."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any, TypeVar

from armorer_guard import GuardSidecar, sign_canonical

Result = TypeVar("Result")


class DemoGuardRuntime:
    """Own the isolated sidecar and its development-only signing identity."""

    def __init__(
        self,
        binary: Path,
        example_root: Path,
        runtime_root: Path,
        model_id: str = "gpt-5.4-mini",
        model_provider: str = "openai",
        model_region: str = "us",
    ) -> None:
        self.binary = binary
        self.example_root = example_root
        self.runtime_root = runtime_root
        self.model_id = model_id
        self.model_provider = model_provider
        self.model_region = model_region
        self.socket_path = runtime_root / "guard.sock"
        self.delegation_key = self.development_key("delegation")
        self.approval_key = self.development_key("approval")
        self.process: subprocess.Popen[str] | None = None
        self.client: GuardSidecar | None = None
        self.manifest: dict[str, Any] = {}

    def __enter__(self) -> DemoGuardRuntime:  # noqa: PYI034 - support Python 3.10
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        manifest_path = self.runtime_root / "agent-manifest.json"
        key_paths = self._write_development_keys()
        self.manifest = self._render_manifest(key_paths, manifest_path)
        self.process = subprocess.Popen(
            [
                str(self.binary),
                "serve",
                "--config",
                str(manifest_path),
                "--data-dir",
                str(self.runtime_root / "data"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self._wait_for_socket()
        except Exception:
            self._stop_process()
            raise
        self.client = GuardSidecar(str(self.socket_path))
        return self

    def __exit__(self, *_error: object) -> None:
        self._stop_process()

    def _stop_process(self) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)
        if self.process.stderr is not None:
            self.process.stderr.close()
        self.process = None

    @property
    def guard(self) -> GuardSidecar:
        if self.client is None:
            raise RuntimeError("Guard sidecar is not running")
        return self.client

    @staticmethod
    def development_key(purpose: str) -> bytes:
        return hashlib.sha256(
            f"armorer-guard-examples-{purpose}-development-only".encode()
        ).digest()

    def content_request(
        self, fixture: dict[str, Any], *, include_model_route: bool = False
    ) -> dict[str, Any]:
        text = fixture["text"]
        content_ref = "content/sha256:" + hashlib.sha256(text.encode()).hexdigest()
        agent = self.manifest["agent"]
        request = {
            "schema_version": "armorer-guard-content-evaluation/v1",
            "request_id": fixture["request_id"],
            "trace_id": "trace/guarded-agent-example",
            "session_id": "session/guarded-agent-example",
            "purpose": fixture.get("purpose", "demo-review"),
            "subject": {
                "agent_id": agent["agent_id"],
                "identity_id": agent["workload_identity"],
                "tenant_id": agent["tenant_id"],
            },
            "segments": [
                {
                    "content_ref": content_ref,
                    "origin": fixture["origin"],
                    "principal_id": fixture.get("principal_id", "user/demo"),
                    "tenant_id": agent["tenant_id"],
                    "trust": "untrusted",
                    "data_classes": fixture.get("data_classes", []),
                    "instruction_authority": "none",
                    "retention": "local_only",
                    "text": text,
                }
            ],
            "destination": None,
        }
        if include_model_route:
            request["model_route"] = {
                "provider": self.model_provider,
                "model_id": self.model_id,
                "region": self.model_region,
                "retention": "provider_zero_retention",
                "allowed_data_classes": ["internal"],
            }
        return request

    def authority_request(self, fixture: dict[str, Any]) -> dict[str, Any]:
        observed_at = int(time.time())
        agent = self.manifest["agent"]
        request = {
            "schema_version": "armorer-guard-authority-request/v2",
            "request_id": fixture["request_id"],
            "subject": agent,
            "delegation": {
                "delegated_by": "user/demo-owner",
                "capability_ids": fixture["delegated_capabilities"],
                "purpose": fixture["purpose"],
                "depth": 1,
                "expires_at": observed_at + 300,
                "signature": "",
            },
            "action": {
                "capability_id": fixture["capability_id"],
                "operation_class": fixture["operation_class"],
                "normalized_arguments": fixture["arguments"],
            },
            "resource": {
                "resource_type": fixture["resource_type"],
                "resource_id": fixture["resource_id"],
                "tenant_id": fixture["resource_tenant"],
                "data_classes": fixture.get("data_classes", []),
            },
            "influence": {
                "content_refs": [],
                "contains_untrusted_content": False,
            },
            "context": {
                "trace_id": "trace/guarded-agent-example",
                "session_id": "session/guarded-agent-example",
                "risk_score": fixture.get("risk_score", 0.1),
                "observed_at": observed_at,
                "approval_receipts": [],
            },
        }
        signing_payload = {
            "request_id": request["request_id"],
            "subject": request["subject"],
            "delegation": {
                name: value
                for name, value in request["delegation"].items()
                if name != "signature"
            },
            "action": request["action"],
            "resource": request["resource"],
        }
        request["delegation"]["signature"] = sign_canonical(
            self.delegation_key, signing_payload
        )
        return request

    def create_approval_challenge(
        self, request: dict[str, Any], required_role: str
    ) -> dict[str, Any]:
        return self.guard.create_approval_challenge(
            {
                "schema_version": "armorer-guard-approval-challenge/v1",
                "authority_request": request,
                "required_role": required_role,
                "expires_at": int(time.time()) + 180,
                "maximum_usage_count": 1,
            }
        )

    def consume_approval(
        self, request: dict[str, Any], receipt: dict[str, Any]
    ) -> None:
        self.guard.consume_approval(
            {
                "schema_version": "armorer-guard-approval-consume/v1",
                "receipt": receipt,
                "authority_request": request,
                "observed_at": int(time.time()),
            }
        )

    def attach_approval(
        self, request: dict[str, Any], receipt: dict[str, Any]
    ) -> dict[str, Any]:
        approved = deepcopy(request)
        approved["context"]["approval_receipts"] = [receipt["receipt_id"]]
        return approved

    def dispatch(
        self, token: dict[str, Any], operation: Callable[[], Result]
    ) -> tuple[dict[str, Any], dict[str, Any], Result]:
        dispatch_request = {
            "schema_version": "armorer-guard-execution-dispatch/v1",
            "token": token,
            "observed_at": int(time.time()),
        }
        grant = self.guard.authorize_execution(dispatch_request)
        outcome = "failed"
        try:
            result = operation()
            outcome = "succeeded"
        finally:
            receipt = self.guard.record_execution(
                {
                    "schema_version": "armorer-guard-execution-report/v1",
                    "token": token,
                    "downstream_dispatched": True,
                    "downstream_outcome": outcome,
                    "observed_at": int(time.time()),
                }
            )
        return grant, receipt, result

    def replay(self, token: dict[str, Any]) -> None:
        self.guard.authorize_execution(
            {
                "schema_version": "armorer-guard-execution-dispatch/v1",
                "token": token,
                "observed_at": int(time.time()),
            }
        )

    def _write_development_keys(self) -> dict[str, Path]:
        key_paths = {}
        for purpose in ("policy", "delegation", "gateway", "approval", "evidence"):
            path = self.runtime_root / f"{purpose}.key"
            path.write_bytes(self.development_key(purpose))
            path.chmod(0o600)
            key_paths[purpose] = path
        return key_paths

    def _render_manifest(
        self, key_paths: dict[str, Path], output_path: Path
    ) -> dict[str, Any]:
        template_path = self.example_root / "config" / "agent-manifest.template.json"
        replacements = {
            "__SOCKET_PATH__": str(self.socket_path),
            "__POLICY_PATH__": str(
                (self.example_root / "config" / "guard-policy.json").resolve()
            ),
            "__POLICY_KEY_PATH__": str(key_paths["policy"].resolve()),
            "__DELEGATION_KEY_PATH__": str(key_paths["delegation"].resolve()),
            "__GATEWAY_KEY_PATH__": str(key_paths["gateway"].resolve()),
            "__APPROVAL_KEY_PATH__": str(key_paths["approval"].resolve()),
            "__EVIDENCE_KEY_PATH__": str(key_paths["evidence"].resolve()),
            "__MODEL_ID__": self.model_id,
            "__MODEL_PROVIDER__": self.model_provider,
            "__MODEL_REGION__": self.model_region,
        }
        rendered = template_path.read_text(encoding="utf-8")
        for marker, value in replacements.items():
            rendered = rendered.replace(marker, value)
        if "__" in rendered:
            raise RuntimeError("agent manifest contains an unresolved placeholder")
        manifest = json.loads(rendered)
        output_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return manifest

    def _wait_for_socket(self) -> None:
        assert self.process is not None
        for _ in range(100):
            if self.socket_path.exists():
                return
            if self.process.poll() is not None:
                stderr = (
                    self.process.stderr.read().strip() if self.process.stderr else ""
                )
                raise RuntimeError(f"Guard sidecar exited during startup: {stderr}")
            time.sleep(0.05)
        raise RuntimeError("Guard sidecar did not create its socket")
