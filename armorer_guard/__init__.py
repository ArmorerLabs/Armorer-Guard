from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
from typing import Any


@dataclass(frozen=True)
class Inspection:
    sanitized_text: str
    suspicious: bool
    reasons: list[str]
    confidence: float


@dataclass(frozen=True)
class CredentialCapture:
    captured_value: str
    sanitized_text: str
    confidence: float
    reasons: list[str]
    credential_type: str
    suggested_key_name: str
    flags: list[str]
    matches: list[Any]


def _binary_name() -> str:
    return "armorer-guard.exe" if os.name == "nt" else "armorer-guard"


def binary_path() -> Path:
    path = Path(__file__).resolve().parent / "bin" / _binary_name()
    if not path.exists():
        raise RuntimeError(f"Armorer Guard binary is missing from package: {path}")
    return path


def _run(mode: str, text: str) -> Any:
    completed = subprocess.run(
        [str(binary_path()), mode],
        input=str(text or ""),
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(f"Armorer Guard failed: {detail}")
    return json.loads(completed.stdout or "{}")


def inspect_input(text: str, context: Any = None) -> Inspection:
    del context
    payload = _run("inspect", text)
    return Inspection(
        sanitized_text=str(payload.get("sanitized_text", "") or ""),
        suspicious=bool(payload.get("suspicious", False)),
        reasons=[str(reason) for reason in payload.get("reasons", []) or []],
        confidence=float(payload.get("confidence", 0.0) or 0.0),
    )


def inspect_output(text: str, context: Any = None) -> Inspection:
    return inspect_input(text, context=context)


def sanitize_text(text: str) -> str:
    payload = _run("sanitize", text)
    return str(payload.get("sanitized_text", "") or "")


def detect_credentials(text: str, context: Any = None) -> CredentialCapture | None:
    del context
    payload = _run("detect-credentials", text)
    if payload is None:
        return None
    return CredentialCapture(
        captured_value=str(payload.get("captured_value", "") or ""),
        sanitized_text=str(payload.get("sanitized_text", "") or ""),
        confidence=float(payload.get("confidence", 0.0) or 0.0),
        reasons=[str(reason) for reason in payload.get("reasons", []) or []],
        credential_type=str(payload.get("credential_type", "") or ""),
        suggested_key_name=str(payload.get("suggested_key_name", "") or ""),
        flags=[str(flag) for flag in payload.get("flags", []) or []],
        matches=list(payload.get("matches", []) or []),
    )


def capabilities() -> dict[str, Any]:
    """Return the Rust binary's machine-readable capability contract.

    The Python package intentionally contains no detection logic. Keeping this
    call routed through the binary makes the Rust implementation the source of
    truth for available lanes, reasons, boundaries, and limitations.
    """

    payload = _run("capabilities", "")
    if not isinstance(payload, dict):
        raise RuntimeError("Armorer Guard returned an invalid capabilities payload")
    return payload
