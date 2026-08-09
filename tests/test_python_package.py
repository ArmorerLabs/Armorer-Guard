from __future__ import annotations

import armorer_guard
import asyncio
import json
from pathlib import Path
import pytest


def test_inspect_redacts_credentials() -> None:
    result = armorer_guard.inspect_input("GH_TOKEN=dummyGithubToken123456789")
    assert "[REDACTED_SECRET_VALUE]" in result.sanitized_text
    assert "dummyGithubToken123456789" not in result.sanitized_text


def test_detect_credentials() -> None:
    result = armorer_guard.detect_credentials("add notion ntn_testSecretToken1234567890abcdef")
    assert result is not None
    assert result.credential_type == "notion"
    assert result.suggested_key_name == "NOTION_API_KEY"


def test_detect_credentials_captures_openrouter_key() -> None:
    text = "here is the key: sk-or-v1-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    result = armorer_guard.detect_credentials(text)
    assert result is not None
    assert result.suggested_key_name == "OPENROUTER_API_KEY"
    assert result.captured_value.startswith("sk-or-v1-")
    assert "[REDACTED_OPENROUTER_KEY]" in result.sanitized_text


def test_inspect_output_flags_credential_leak() -> None:
    result = armorer_guard.inspect_output("The token is 123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijk")
    assert result.suspicious is True
    assert "[REDACTED_TELEGRAM_TOKEN]" in result.sanitized_text


def test_sanitize_text_redacts_lowercase_generic_secret_assignment() -> None:
    sanitized = armorer_guard.sanitize_text("password: hunter22supersecretvalue")
    assert "hunter22supersecretvalue" not in sanitized
    assert "[REDACTED_SECRET_VALUE]" in sanitized


def test_capabilities_are_rust_owned() -> None:
    capabilities = armorer_guard.capabilities()
    assert capabilities["implementation_language"] == "rust"
    assert capabilities["boundaries"]["python_detection_logic"].startswith("none")
    assert "mcp-proxy" in capabilities["cli_modes"]
    assert {lane["id"] for lane in capabilities["lanes"]} >= {
        "credential_lane",
        "semantic_lane",
        "similarity_lane",
        "policy_lane",
        "mcp_proxy_lane",
    }


def test_package_version_matches_binary() -> None:
    version_info = armorer_guard.version_info()
    assert armorer_guard.__version__ == version_info["version"]


def test_canonical_contract_vector_matches_rust() -> None:
    fixture = json.loads(
        (Path(__file__).parents[1] / "fixtures/canonical-contract-vectors.json").read_text()
    )["vectors"][0]
    assert armorer_guard.canonical_json(fixture["value"]) == fixture["canonical_json"]
    assert armorer_guard.canonical_digest(fixture["value"]) == fixture["digest"]
    assert (
        armorer_guard.sign_canonical(bytes([7]) * 32, fixture["value"])
        == fixture["signature"]
    )


def test_protected_capability_never_hides_a_missing_failure_receipt() -> None:
    class Sidecar:
        def action(self, _request):
            return {"effect": "allow", "execution_token": {"token_id": "token/1"}}

        def authorize_execution(self, _request):
            return {}

        def record_execution(self, _request):
            raise armorer_guard.GuardSidecarError("spool unavailable")

    @armorer_guard.protect_capability(Sidecar(), lambda *_args, **_kwargs: {})
    def protected(*_args, **_kwargs):
        raise ValueError("downstream failed")

    with pytest.raises(armorer_guard.GuardSidecarError) as captured:
        asyncio.run(protected())
    assert captured.value.code == "RECEIPT_RECORDING_FAILED"


def test_sidecar_routes_match_shared_adapter_conformance_fixture() -> None:
    fixture = json.loads(
        (Path(__file__).parents[1] / "fixtures/adapter-conformance.json").read_text()
    )
    sidecar = armorer_guard.GuardSidecar()
    calls: list[tuple[str, object, str]] = []

    def record(path: str, payload: object = None, method: str = "POST") -> dict:
        calls.append((path, payload, method))
        return {}

    sidecar.request = record  # type: ignore[method-assign]
    marker = {"fixture": True}
    for route in fixture["routes"]:
        operation = getattr(sidecar, route["python"])
        if route["method"] == "GET":
            operation()
            expected_payload = None
        else:
            operation(marker)
            expected_payload = marker
        assert calls.pop() == (route["path"], expected_payload, route["method"])


def test_remote_sidecar_requires_complete_mtls_identity() -> None:
    with pytest.raises(ValueError, match="mTLS requires"):
        armorer_guard.GuardSidecar(mtls_endpoint=("guard.internal", 8443))
