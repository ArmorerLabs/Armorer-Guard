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
