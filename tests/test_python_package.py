from __future__ import annotations

import asyncio

import pytest

import armorer_guard


def test_canonical_values_are_stable() -> None:
    value = {"tenant": "tenant/example", "args": {"ticket": 42}, "allowed": True}
    assert armorer_guard.canonical_json(value) == (
        '{"allowed":true,"args":{"ticket":42},"tenant":"tenant/example"}'
    )
    assert armorer_guard.canonical_digest(value).startswith("sha256:")
    assert armorer_guard.sign_canonical(bytes([7]) * 32, value).startswith(
        "hmac-sha256:"
    )


def test_sidecar_routes_use_only_public_runtime_endpoints() -> None:
    sidecar = armorer_guard.GuardSidecar(socket_path="/tmp/guard-sdk-test.sock")
    calls: list[tuple[str, object, str]] = []

    def record(path: str, payload: object = None, method: str = "POST") -> dict:
        calls.append((path, payload, method))
        return {}

    sidecar.request = record  # type: ignore[method-assign]
    marker = {"fixture": True}
    sidecar.input(marker)
    sidecar.model_request(marker)
    sidecar.model_response(marker)
    sidecar.action(marker)
    sidecar.tool_result(marker)
    sidecar.output(marker)
    sidecar.capabilities()
    sidecar.operational_status()
    sidecar.authorize_execution(marker)
    sidecar.record_execution(marker)
    assert calls == [
        ("/v1/input/evaluate", marker, "POST"),
        ("/v1/model/request/evaluate", marker, "POST"),
        ("/v1/model/response/evaluate", marker, "POST"),
        ("/v1/action/evaluate", marker, "POST"),
        ("/v1/tool/result/evaluate", marker, "POST"),
        ("/v1/output/evaluate", marker, "POST"),
        ("/v1/capabilities", None, "GET"),
        ("/v1/operations/status", None, "GET"),
        ("/v1/executions/authorize", marker, "POST"),
        ("/v1/executions/receipts", marker, "POST"),
    ]


def test_protected_effect_requires_explicit_dispatch_authorization() -> None:
    executed = False

    class Sidecar:
        def action(self, _request):
            return {"effect": "allow", "execution_token": {"token_id": "token/1"}}

        def authorize_execution(self, _request):
            return {"authorized": False}

    @armorer_guard.protect_capability(Sidecar(), lambda *_args, **_kwargs: {})
    def protected(*_args, **_kwargs):
        nonlocal executed
        executed = True

    with pytest.raises(armorer_guard.GuardSidecarError) as captured:
        asyncio.run(protected())
    assert captured.value.code == "EXECUTION_NOT_AUTHORIZED"
    assert executed is False


def test_protected_effect_requires_execution_receipt() -> None:
    class Sidecar:
        def action(self, _request):
            return {"effect": "allow", "execution_token": {"token_id": "token/1"}}

        def authorize_execution(self, _request):
            return {"authorized": True}

        def record_execution(self, _request):
            return {}

    @armorer_guard.protect_capability(Sidecar(), lambda *_args, **_kwargs: {})
    def protected(*_args, guard_execution_token, **_kwargs):
        assert guard_execution_token["token_id"] == "token/1"
        return "ok"

    with pytest.raises(armorer_guard.GuardSidecarError) as captured:
        asyncio.run(protected())
    assert captured.value.code == "RECEIPT_MISSING"


def test_protected_effect_returns_result_with_receipt() -> None:
    class Sidecar:
        def action(self, _request):
            return {"effect": "allow", "execution_token": {"token_id": "token/1"}}

        def authorize_execution(self, _request):
            return {"authorized": True}

        def record_execution(self, _request):
            return {"receipt_id": "receipt/1"}

    @armorer_guard.protect_capability(Sidecar(), lambda *_args, **_kwargs: {})
    def protected(*_args, guard_execution_token, **_kwargs):
        assert guard_execution_token["token_id"] == "token/1"
        return "ok"

    execution = asyncio.run(protected())
    assert execution.result == "ok"
    assert execution.execution_receipt == {"receipt_id": "receipt/1"}


def test_generic_model_adapter_fails_closed_on_transformed_content() -> None:
    envelope = {
        "segments": [{"content_ref": "content/sha256:fixture", "text": "original"}]
    }

    class Sidecar:
        def model_request(self, _request):
            return {
                "effect": "redact_and_allow",
                "segments": [
                    {
                        "content_ref": "content/sha256:fixture",
                        "sanitized_text": "redacted",
                    }
                ],
            }

    adapter = armorer_guard.OpenAICompatibleAdapter(Sidecar())
    with pytest.raises(armorer_guard.GuardDenied) as captured:
        asyncio.run(adapter.invoke(envelope, lambda: "not reached", lambda _: envelope))
    assert captured.value.code == "CONTENT_TRANSFORM_UNSUPPORTED"


def test_remote_guard_requires_complete_mtls_identity() -> None:
    with pytest.raises(ValueError, match="mTLS requires"):
        armorer_guard.GuardSidecar(mtls_endpoint=("guard.internal", 8443))


def test_request_path_rejects_header_injection() -> None:
    sidecar = armorer_guard.GuardSidecar(socket_path="/tmp/guard-sdk-test.sock")
    with pytest.raises(ValueError, match="versioned API path"):
        sidecar.request("/v1/status\r\nInjected: true", method="GET")


def test_client_package_contains_no_embedded_runtime_api() -> None:
    assert not hasattr(armorer_guard, "binary_path")
    assert not hasattr(armorer_guard, "inspect_input")
