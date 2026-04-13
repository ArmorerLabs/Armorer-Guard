from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecretMatch:
    secret_type: str
    value: str
    redaction: str
    start: int
    end: int


@dataclass(frozen=True)
class GuardInspection:
    sanitized_text: str
    suspicious: bool
    reasons: list[str] = field(default_factory=list)
    confidence: float = 0.0
    flags: list[str] = field(default_factory=list)
    matches: list[SecretMatch] = field(default_factory=list)


@dataclass(frozen=True)
class CredentialCaptureResult:
    captured_value: str
    sanitized_text: str
    confidence: float
    reasons: list[str] = field(default_factory=list)
    credential_type: str = ""
    suggested_key_name: str = ""
    flags: list[str] = field(default_factory=list)
    matches: list[SecretMatch] = field(default_factory=list)
