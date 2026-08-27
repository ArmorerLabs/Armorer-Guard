"""Dependency-free client for an Armorer-provisioned Guard runtime."""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import os
import re
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

DEFAULT_MAX_BODY_BYTES = 1024 * 1024
_API_PATH = re.compile(r"/v1/[A-Za-z0-9._~/-]+")


class GuardSidecarError(RuntimeError):
    def __init__(self, message: str, *, code: Any = None, decision: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.decision = decision


class GuardApprovalRequired(GuardSidecarError):
    pass


class GuardDenied(GuardSidecarError):
    pass


@dataclass(frozen=True)
class GuardedExecution:
    """A downstream result bound to the Guard receipt for that effect."""

    result: Any
    execution_receipt: dict[str, Any]


class GuardSidecar:
    """Fail-closed client for the local socket or authenticated remote API."""

    def __init__(
        self,
        socket_path: str | None = None,
        timeout: float = 2.0,
        *,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        mtls_endpoint: tuple[str, int] | None = None,
        ca_file: str | None = None,
        certificate_file: str | None = None,
        private_key_file: str | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")
        self.socket_path = socket_path or os.environ.get("ARMORER_GUARD_SOCKET")
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes
        self.mtls_endpoint = mtls_endpoint
        self.ssl_context: ssl.SSLContext | None = None
        if mtls_endpoint is not None:
            if not all((ca_file, certificate_file, private_key_file)):
                raise ValueError(
                    "mTLS requires CA, client certificate, and private key files"
                )
            context = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH, cafile=ca_file
            )
            context.load_cert_chain(certificate_file, private_key_file)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            self.ssl_context = context
        elif not self.socket_path:
            raise ValueError(
                "socket_path or ARMORER_GUARD_SOCKET is required when mTLS is not configured"
            )

    def request(self, path: str, payload: Any = None, method: str = "POST") -> Any:
        if not _API_PATH.fullmatch(path):
            raise ValueError("Guard request path must be a versioned API path")
        if method not in {"GET", "POST"}:
            raise ValueError("Guard client supports only GET and POST")
        try:
            body = (
                b""
                if payload is None
                else json.dumps(
                    payload,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode()
            )
        except (TypeError, ValueError) as error:
            raise GuardSidecarError(
                "Guard request is not JSON serializable", code="INVALID_REQUEST"
            ) from error
        if len(body) > self.max_body_bytes:
            raise GuardSidecarError(
                "Guard request exceeds the configured size limit",
                code="REQUEST_TOO_LARGE",
            )
        wire = (
            f"{method} {path} HTTP/1.1\r\n"
            "Host: armorer-guard.local\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode() + body
        received = bytearray()
        try:
            named_pipe = False
            if self.mtls_endpoint is not None:
                if self.ssl_context is None:
                    raise GuardSidecarError(
                        "Guard mTLS context was not initialized",
                        code="INVALID_CLIENT_CONFIGURATION",
                    )
                raw = socket.create_connection(self.mtls_endpoint, timeout=self.timeout)
                connection = self.ssl_context.wrap_socket(
                    raw, server_hostname=self.mtls_endpoint[0]
                )
            elif os.name == "nt" and self.socket_path.startswith("\\\\.\\pipe\\"):
                connection = open(self.socket_path, "r+b", buffering=0)  # noqa: SIM115
                named_pipe = True
            else:
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(self.timeout)
                connection.connect(self.socket_path)
            with connection:
                if named_pipe:
                    connection.write(wire)
                    connection.flush()
                    while chunk := connection.read(65536):
                        received.extend(chunk)
                        self._check_response_size(received)
                else:
                    connection.sendall(wire)
                    while chunk := connection.recv(65536):
                        received.extend(chunk)
                        self._check_response_size(received)
        except GuardSidecarError:
            raise
        except (OSError, ssl.SSLError) as error:
            raise GuardSidecarError(
                f"Armorer Guard unavailable: {error}", code="SIDECAR_UNAVAILABLE"
            ) from error
        header, separator, response_body = bytes(received).partition(b"\r\n\r\n")
        if not separator:
            raise GuardSidecarError(
                "Guard returned an invalid HTTP response", code="INVALID_RESPONSE"
            )
        try:
            status_line = header.split(b"\r\n", 1)[0]
            protocol, raw_status, *_ = status_line.split(b" ")
            if protocol not in {b"HTTP/1.0", b"HTTP/1.1"}:
                raise ValueError("unsupported HTTP protocol")
            status = int(raw_status)
            value = json.loads(response_body or b"{}")
        except (ValueError, IndexError, json.JSONDecodeError) as error:
            raise GuardSidecarError(
                "Guard returned an invalid response", code="INVALID_RESPONSE"
            ) from error
        if not 200 <= status < 300:
            error_message = (
                value.get("error", f"Guard returned HTTP {status}")
                if isinstance(value, dict)
                else f"Guard returned HTTP {status}"
            )
            reason_code = (
                value.get("reason_code", status) if isinstance(value, dict) else status
            )
            raise GuardSidecarError(
                str(error_message), code=reason_code, decision=value
            )
        return value

    def _check_response_size(self, received: bytearray) -> None:
        if len(received) > self.max_body_bytes + 64 * 1024:
            raise GuardSidecarError(
                "Guard response exceeds the configured size limit",
                code="RESPONSE_TOO_LARGE",
            )

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

    def authorize_execution(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/executions/authorize", request)

    def record_execution(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("/v1/executions/receipts", request)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def sign_canonical(key: bytes, value: Any) -> str:
    return (
        "hmac-sha256:"
        + hmac.new(key, canonical_json(value).encode(), hashlib.sha256).hexdigest()
    )


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def protect_capability(sidecar: Any, authority_request: Callable[..., Any]):
    """Require a Guard decision, one-use dispatch, and execution receipt."""

    def decorate(function: Callable[..., Any]):
        async def guarded(*args: Any, **kwargs: Any) -> Any:
            request = await _maybe_await(authority_request(*args, **kwargs))
            decision = await _maybe_await(sidecar.action(request))
            if decision.get("effect") == "require_approval":
                raise GuardApprovalRequired(
                    "Armorer Guard requires approval",
                    code="APPROVAL_REQUIRED",
                    decision=decision,
                )
            token = decision.get("execution_token")
            if decision.get("effect") != "allow" or not token:
                raise GuardDenied(
                    "Armorer Guard denied the operation",
                    code="GUARD_DENIED",
                    decision=decision,
                )
            dispatch = await _maybe_await(
                sidecar.authorize_execution(
                    {
                        "schema_version": "armorer-guard-execution-dispatch/v1",
                        "token": token,
                        "observed_at": int(time.time()),
                    }
                )
            )
            if dispatch.get("authorized") is not True:
                raise GuardSidecarError(
                    "Guard did not authorize the execution token",
                    code="EXECUTION_NOT_AUTHORIZED",
                    decision=dispatch,
                )
            try:
                result = await _maybe_await(
                    function(*args, guard_execution_token=token, **kwargs)
                )
            except Exception as execution_error:
                try:
                    await _maybe_await(
                        sidecar.record_execution(
                            {
                                "schema_version": "armorer-guard-execution-report/v1",
                                "token": token,
                                "downstream_dispatched": True,
                                "downstream_outcome": "failed",
                                "observed_at": int(time.time()),
                            }
                        )
                    )
                # Receipt APIs are user-provided in adapters and may raise any
                # exception type; preserve both failures for incident handling.
                except Exception as receipt_error:  # noqa: BLE001
                    raise GuardSidecarError(
                        "Downstream execution failed and its Guard receipt could not be recorded",
                        code="RECEIPT_RECORDING_FAILED",
                        decision={
                            "execution_error": repr(execution_error),
                            "receipt_error": repr(receipt_error),
                        },
                    ) from execution_error
                raise
            receipt = await _maybe_await(
                sidecar.record_execution(
                    {
                        "schema_version": "armorer-guard-execution-report/v1",
                        "token": token,
                        "downstream_dispatched": True,
                        "downstream_outcome": "succeeded",
                        "observed_at": int(time.time()),
                    }
                )
            )
            if (
                not isinstance(receipt.get("receipt_id"), str)
                or not receipt["receipt_id"]
            ):
                raise GuardSidecarError(
                    "Guard did not return an execution receipt",
                    code="RECEIPT_MISSING",
                    decision=receipt,
                )
            return GuardedExecution(result=result, execution_receipt=receipt)

        return guarded

    return decorate
