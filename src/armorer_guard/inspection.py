from __future__ import annotations

import re
from typing import Iterable

from .models import CredentialCaptureResult, GuardInspection, SecretMatch

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    ("openai", re.compile(r"(?i)\b(sk-(?!or-v1-)(?:proj-)?[A-Za-z0-9_-]{20,})\b"), "[REDACTED_OPENAI_KEY]", "OPENAI_API_KEY"),
    ("openrouter", re.compile(r"(?i)\b(sk-or-v1-[A-Za-z0-9]{32,})\b"), "[REDACTED_OPENROUTER_KEY]", "OPENROUTER_API_KEY"),
    ("anthropic", re.compile(r"(?i)\b(sk-ant-[A-Za-z0-9_-]{20,})\b"), "[REDACTED_ANTHROPIC_KEY]", "ANTHROPIC_API_KEY"),
    ("gemini", re.compile(r"(?i)\b(AIza[0-9A-Za-z\-_]{20,})\b"), "[REDACTED_GEMINI_KEY]", "GEMINI_API_KEY"),
    ("telegram_bot", re.compile(r"\b(\d{5,}:[A-Za-z0-9_-]{20,})\b"), "[REDACTED_TELEGRAM_TOKEN]", "TELEGRAM_BOT_TOKEN"),
    ("github", re.compile(r"(?i)\b(gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), "[REDACTED_GITHUB_TOKEN]", "GH_TOKEN"),
    ("jwt", re.compile(r"(?i)\b(eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b"), "[REDACTED_JWT]", ""),
)

_GENERIC_ASSIGNMENT = re.compile(
    r"(?ix)"
    r"\b(?:api[\s_-]*key|access[\s_-]*token|token|secret|password|passwd)\b"
    r"\s*(?:is|=|:)\s*"
    r"([A-Za-z0-9._~:/+=-]{12,})"
)

_EXFILTRATION_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"ignore\s+(all\s+)?previous\s+(instr\w+|insrtuction\w*)", re.I), "heuristic:ignore previous instructions", "Prompt injection"),
    (re.compile(r"\b(system\s+prompt|developer\s+(message|prompt|instructions?))\b", re.I), "heuristic:system prompt", "Prompt injection"),
    (re.compile(r"\b(reveal|export|dump|show)\b.*\b(secret|token|credential|password|api key)s?\b", re.I), "heuristic:reveal secrets", "Sensitive data"),
    (re.compile(r"\bpass(word|codes?)\b", re.I), "heuristic:password", "Sensitive data"),
    (re.compile(r"\bcredential(s)?\b", re.I), "heuristic:credentials", "Sensitive data"),
    (re.compile(r"\bapi\s+key(s)?\b", re.I), "heuristic:api key", "Sensitive data"),
    (re.compile(r"\bexfiltrat\w*\b", re.I), "heuristic:exfiltrate", "Data exfiltration"),
    (re.compile(r"\b(disable\s+security|bypass\s+safety)\b", re.I), "heuristic:disable security", "Safety bypass"),
)


def _ordered_matches(text: str) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    for secret_type, pattern, redaction, _suggested_key in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            matches.append(
                SecretMatch(
                    secret_type=secret_type,
                    value=match.group(1),
                    redaction=redaction,
                    start=match.start(1),
                    end=match.end(1),
                )
            )
    for match in _GENERIC_ASSIGNMENT.finditer(text):
        matches.append(
            SecretMatch(
                secret_type="generic_secret",
                value=match.group(1),
                redaction="[REDACTED_SECRET]",
                start=match.start(1),
                end=match.end(1),
            )
        )
    matches.sort(key=lambda item: (item.start, item.end))
    return matches


def sanitize_text(text: str) -> str:
    sanitized = str(text or "")
    for match in reversed(_ordered_matches(sanitized)):
        sanitized = sanitized[: match.start] + match.redaction + sanitized[match.end :]
    sanitized = re.sub(r"(?i)\b(bearer\s+[a-z0-9\-\._~\+\/]+=*)\b", "[REDACTED_BEARER]", sanitized)
    sanitized = re.sub(r"(?i)\b([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})\b", "[REDACTED_EMAIL]", sanitized)
    sanitized = re.sub(r"(?i)\b(\+?[0-9][0-9\-\(\) ]{8,}[0-9])\b", "[REDACTED_PHONE]", sanitized)
    return sanitized


def _heuristic_findings(text: str) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    flags: list[str] = []
    for pattern, reason, flag in _EXFILTRATION_PATTERNS:
        if pattern.search(text):
            reasons.append(reason)
            if flag not in flags:
                flags.append(flag)
    return reasons, flags


def _suggested_key_name(matches: Iterable[SecretMatch]) -> str:
    for match in matches:
        for secret_type, _pattern, _redaction, suggested_key in _SECRET_PATTERNS:
            if match.secret_type == secret_type and suggested_key:
                return suggested_key
        if match.secret_type == "generic_secret":
            return "API_KEY"
    return ""


def detect_credentials(text: str, context=None) -> CredentialCaptureResult | None:
    original = str(text or "").strip()
    if not original:
        return None
    matches = _ordered_matches(original)
    if not matches:
        return None
    first = matches[0]
    suggested_key = _suggested_key_name(matches)
    reasons = ["detected:credential"]
    flags = ["Sensitive data"]
    if "password" in original.lower():
        reasons.append("heuristic:password")
    confidence = 0.99 if first.secret_type != "generic_secret" else 0.75
    return CredentialCaptureResult(
        captured_value=first.value,
        sanitized_text=sanitize_text(original),
        confidence=confidence,
        reasons=reasons,
        credential_type=first.secret_type,
        suggested_key_name=suggested_key,
        flags=flags,
        matches=matches,
    )


def _inspect(text: str, *, is_output: bool) -> GuardInspection:
    original = str(text or "")
    matches = _ordered_matches(original)
    reasons, flags = _heuristic_findings(original)
    if matches:
        reasons.append("detected:credential")
        if "Sensitive data" not in flags:
            flags.append("Sensitive data")
    suspicious = bool(reasons or matches)
    confidence = 0.0
    if matches:
        confidence = max(confidence, 0.95 if any(m.secret_type != "generic_secret" for m in matches) else 0.72)
    if reasons:
        confidence = max(confidence, 0.84 if is_output else 0.78)
    return GuardInspection(
        sanitized_text=sanitize_text(original),
        suspicious=suspicious,
        reasons=sorted(set(reasons)),
        confidence=round(confidence, 2),
        flags=flags,
        matches=matches,
    )


def inspect_input(text: str, context=None) -> GuardInspection:
    return _inspect(text, is_output=False)


def inspect_output(text: str, context=None) -> GuardInspection:
    return _inspect(text, is_output=True)
