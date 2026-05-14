from __future__ import annotations

import armorer_guard


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
