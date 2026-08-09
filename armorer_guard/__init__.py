from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import subprocess
import socket
import ssl
import time
import inspect as _inspect
import hashlib
import hmac
from typing import Any


def _source_tree_version() -> str | None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    if not pyproject.exists():
        return None
    for line in pyproject.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("version = "):
            return line.split("=", 1)[1].strip().strip('"')
    return None


try:
    __version__ = _source_tree_version() or version("armorer-guard")
except PackageNotFoundError:
    __version__ = "0.4.1"


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


class GuardSidecarError(RuntimeError):
    def __init__(self, message: str, *, code: Any = None, decision: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.decision = decision


class GuardApprovalRequired(GuardSidecarError):
    pass


class GuardDenied(GuardSidecarError):
    pass


class GuardSidecar:
    """Dependency-free client for the local Guard Unix-socket API.

    All security-sensitive methods fail closed when the sidecar is unavailable.
    """

    def __init__(
        self,
        socket_path: str | None = None,
        timeout: float = 2.0,
        *,
        mtls_endpoint: tuple[str, int] | None = None,
        ca_file: str | None = None,
        certificate_file: str | None = None,
        private_key_file: str | None = None,
    ) -> None:
        self.socket_path = socket_path or os.environ.get(
            "ARMORER_GUARD_SOCKET", "/tmp/armorer-guard.sock"
        )
        self.timeout = timeout
        self.mtls_endpoint = mtls_endpoint
        self.ssl_context: ssl.SSLContext | None = None
        if mtls_endpoint is not None:
            if not all((ca_file, certificate_file, private_key_file)):
                raise ValueError("mTLS requires CA, client certificate, and private key files")
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
            context.load_cert_chain(certificate_file, private_key_file)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            self.ssl_context = context

    def request(self, path: str, payload: Any = None, method: str = "POST") -> Any:
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        wire = (
            f"{method} {path} HTTP/1.1\r\n"
            "Host: armorer-guard.local\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode() + body
        received = bytearray()
        try:
            is_named_pipe = False
            if self.mtls_endpoint is not None:
                assert self.ssl_context is not None
                raw = socket.create_connection(self.mtls_endpoint, timeout=self.timeout)
                connection = self.ssl_context.wrap_socket(
                    raw, server_hostname=self.mtls_endpoint[0]
                )
            elif os.name == "nt" and self.socket_path.startswith("\\\\.\\pipe\\"):
                connection = open(self.socket_path, "r+b", buffering=0)  # noqa: SIM115
                is_named_pipe = True
            else:
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(self.timeout)
                connection.connect(self.socket_path)
            with connection:
                if is_named_pipe:
                    connection.write(wire)
                    connection.flush()
                    while chunk := connection.read(65536):
                        received.extend(chunk)
                else:
                    connection.sendall(wire)
                    while chunk := connection.recv(65536):
                        received.extend(chunk)
        except OSError as error:
            raise GuardSidecarError(
                f"Armorer Guard sidecar unavailable: {error}", code="SIDECAR_UNAVAILABLE"
            ) from error
        header, separator, response_body = bytes(received).partition(b"\r\n\r\n")
        if not separator:
            raise GuardSidecarError("Armorer Guard returned an invalid HTTP response")
        try:
            status = int(header.split(b" ", 2)[1])
            value = json.loads(response_body or b"{}")
        except (ValueError, IndexError, json.JSONDecodeError) as error:
            raise GuardSidecarError("Armorer Guard returned an invalid response") from error
        if not 200 <= status < 300:
            raise GuardSidecarError(
                str(value.get("error", f"Guard returned HTTP {status}")),
                code=value.get("reason_code", status),
                decision=value,
            )
        return value

    def input(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/input/evaluate", request)

    def context(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/context/evaluate", request)

    def model_request(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/model/request/evaluate", request)

    def model_response(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/model/response/evaluate", request)

    def action(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/action/evaluate", request)

    def output(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/output/evaluate", request)

    def tool_result(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/tool/result/evaluate", request)

    def memory_write(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/memory/write/evaluate", request)

    def memory_read(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/memory/read/evaluate", request)

    def inter_agent(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/inter-agent/evaluate", request)

    def capabilities(self) -> list[dict[str, Any]]:
        return self.request("/v1/capabilities", method="GET")

    def features(self) -> dict[str, Any]:
        return self.request("/v1/features", method="GET")

    def enforcement_coverage(self) -> dict[str, Any]:
        return self.request("/v1/enforcement/coverage", method="GET")

    def operational_status(self) -> dict[str, Any]:
        return self.request("/v1/operations/status", method="GET")

    def create_approval_challenge(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/approvals/challenges", request)

    def consume_approval(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/approvals/consume", request)

    def record_execution(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/executions/receipts", request)

    def authorize_execution(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/executions/authorize", request)

    def access_evidence(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/evidence/access", request)

    def broker_http(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/gateway/http", request)

    def broker_filesystem(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/gateway/filesystem", request)

    def replay_trace(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/replay/traces", request)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def sign_canonical(key: bytes, value: Any) -> str:
    return "hmac-sha256:" + hmac.new(
        key, canonical_json(value).encode(), hashlib.sha256
    ).hexdigest()


def protect_capability(sidecar: GuardSidecar, authority_request: Any):
    """Decorator for Python/CrewAI/LangGraph tools.

    The authority_request callable receives the same args as the tool and must
    return the normalized v2 request. The wrapped tool receives the execution
    token as the keyword-only ``guard_execution_token`` argument.
    """

    def decorate(function: Any):
        async def guarded(*args: Any, **kwargs: Any) -> Any:
            request = authority_request(*args, **kwargs)
            if _inspect.isawaitable(request):
                request = await request
            decision = sidecar.action(request)
            if decision.get("effect") == "require_approval":
                raise GuardApprovalRequired("Armorer Guard requires approval", decision=decision)
            token = decision.get("execution_token")
            if decision.get("effect") != "allow" or not token:
                raise GuardDenied("Armorer Guard denied the operation", decision=decision)
            sidecar.authorize_execution(
                {
                    "schema_version": "armorer-guard-execution-dispatch/v1",
                    "token": token,
                    "observed_at": int(time.time()),
                }
            )
            try:
                result = function(*args, guard_execution_token=token, **kwargs)
                if _inspect.isawaitable(result):
                    result = await result
            except Exception as execution_error:
                try:
                    sidecar.record_execution(
                        {
                            "schema_version": "armorer-guard-execution-report/v1",
                            "token": token,
                            "downstream_dispatched": True,
                            "downstream_outcome": "failed",
                            "observed_at": int(time.time()),
                        }
                    )
                except GuardSidecarError as receipt_error:
                    raise GuardSidecarError(
                        "Downstream execution failed and its Guard receipt could not be recorded",
                        code="RECEIPT_RECORDING_FAILED",
                        decision={
                            "execution_error": repr(execution_error),
                            "receipt_error": repr(receipt_error),
                        },
                    ) from execution_error
                raise
            sidecar.record_execution(
                {
                    "schema_version": "armorer-guard-execution-report/v1",
                    "token": token,
                    "downstream_dispatched": True,
                    "downstream_outcome": "succeeded",
                    "observed_at": int(time.time()),
                }
            )
            return result

        return guarded

    return decorate


def _binary_name() -> str:
    return "armorer-guard.exe" if os.name == "nt" else "armorer-guard"


def binary_path() -> Path:
    source_tree_binary = Path(__file__).resolve().parents[1] / "target" / "release" / _binary_name()
    if source_tree_binary.exists():
        return source_tree_binary

    path = Path(__file__).resolve().parent / "bin" / _binary_name()
    if path.exists():
        return path

    raise RuntimeError(
        "Armorer Guard binary is missing. Install a wheel that includes the binary "
        "or run `cargo build --release` from the source checkout."
    )


def _run(mode: str, text: str, context: Any = None) -> Any:
    payload = str(text or "")
    if context is not None and mode == "inspect":
        mode = "inspect-json"
        payload = json.dumps({"text": payload, "context": context}, separators=(",", ":"))
    completed = subprocess.run(
        [str(binary_path()), mode],
        input=payload,
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
    payload = _run("inspect", text, context=context)
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


def version_info() -> dict[str, Any]:
    payload = _run("version", "")
    if not isinstance(payload, dict):
        raise RuntimeError("Armorer Guard returned an invalid version payload")
    return payload


def evaluate_policy(policy_bundle: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    payload = _run(
        "policy-evaluate",
        json.dumps({"policy_bundle": policy_bundle, "request": request}, separators=(",", ":")),
    )
    if not isinstance(payload, dict) or payload.get("authority_expanded") is not False:
        raise RuntimeError("Armorer Guard returned an invalid policy decision")
    return payload
