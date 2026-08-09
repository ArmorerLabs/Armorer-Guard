#!/usr/bin/env python3
"""Measure warm local Guard boundary latency and emit machine-readable SLO evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import socket
import statistics
import time
from pathlib import Path
from typing import Any

from armorer_guard import sign_canonical


def request(socket_path: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    wire = (
        f"POST {path} HTTP/1.1\r\nHost: armorer-guard.local\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body
    response = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(socket_path)
        connection.sendall(wire)
        while chunk := connection.recv(65536):
            response.extend(chunk)
    header, separator, response_body = bytes(response).partition(b"\r\n\r\n")
    if not separator or int(header.split(b" ", 2)[1]) != 200:
        raise RuntimeError(response.decode(errors="replace"))
    return json.loads(response_body)


def percentile(samples: list[float], fraction: float) -> float:
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def measure(iterations: int, operation: Any) -> dict[str, float]:
    samples = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        operation()
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
    return {
        "p50_ms": round(percentile(samples, 0.50), 3),
        "p95_ms": round(percentile(samples, 0.95), 3),
        "p99_ms": round(percentile(samples, 0.99), 3),
        "mean_ms": round(statistics.fmean(samples), 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--delegation-key-file", required=True)
    parser.add_argument("--iterations", type=int, default=250)
    parser.add_argument("--output")
    parser.add_argument("--artifact")
    args = parser.parse_args()
    if not 10 <= args.iterations <= 10_000:
        raise SystemExit("iterations must be between 10 and 10000")
    key = Path(args.delegation_key_file).read_bytes()
    if len(key) < 32:
        raise SystemExit("delegation key must contain at least 32 bytes")

    counter = 0
    action_effect: str | None = None

    def authority() -> None:
        nonlocal counter, action_effect
        counter += 1
        observed_at = int(time.time())
        value = {
            "schema_version": "armorer-guard-authority-request/v2",
            "request_id": f"benchmark/action/{counter}",
            "subject": {
                "agent_id": "example-agent",
                "workload_identity": "spiffe://example/agents/example-agent",
                "tenant_id": "tenant/example",
            },
            "delegation": {
                "delegated_by": "benchmark/operator",
                "capability_ids": ["record.read"],
                "purpose": "example-review",
                "depth": 1,
                "expires_at": observed_at + 300,
                "signature": "",
            },
            "action": {
                "capability_id": "record.read",
                "operation_class": "read",
                "normalized_arguments": {"record_id": "record/benchmark"},
            },
            "resource": {
                "resource_type": "record",
                "resource_id": "record/benchmark",
                "tenant_id": "tenant/example",
                "data_classes": [],
            },
            "influence": {"content_refs": [], "contains_untrusted_content": False},
            "context": {
                "trace_id": "trace/benchmark",
                "session_id": "session/benchmark",
                "risk_score": 0.05,
                "observed_at": observed_at,
                "approval_receipts": [],
            },
        }
        signing_payload = {
            "request_id": value["request_id"],
            "subject": value["subject"],
            "delegation": {k: v for k, v in value["delegation"].items() if k != "signature"},
            "action": value["action"],
            "resource": value["resource"],
        }
        value["delegation"]["signature"] = sign_canonical(key, signing_payload)
        decision = request(args.socket, "/v1/action/evaluate", value)
        if decision["effect"] not in {"allow", "deny", "require_approval"}:
            raise RuntimeError(f"benchmark action returned an invalid decision: {decision}")
        action_effect = decision["effect"]

    text = "Summarize the approved record for the case owner."
    digest = hashlib.sha256(text.encode()).hexdigest()

    def inspect_text() -> None:
        request(
            args.socket,
            "/v1/input/evaluate",
            {
                "schema_version": "armorer-guard-content-evaluation/v1",
                "request_id": f"benchmark/input/{time.perf_counter_ns()}",
                "trace_id": "trace/benchmark",
                "session_id": "session/benchmark",
                "subject": {
                    "agent_id": "example-agent",
                    "identity_id": "spiffe://example/agents/example-agent",
                    "tenant_id": "tenant/example",
                },
                "segments": [{
                    "content_ref": f"content/sha256:{digest}",
                    "origin": "user_message",
                    "principal_id": "benchmark/operator",
                    "tenant_id": "tenant/example",
                    "trust": "trusted",
                    "data_classes": [],
                    "instruction_authority": "user",
                    "retention": "ephemeral",
                    "text": text,
                }],
            },
        )

    for _ in range(10):
        authority()
        inspect_text()
    result = {
        "schema_version": "armorer-guard-slo-benchmark/v1",
        "captured_at": int(time.time()),
        "platform": platform.platform(),
        "transport": "unix_socket",
        "iterations": args.iterations,
        "action_decision_effect": action_effect,
        "action": measure(args.iterations, authority),
        "ordinary_text_inspection": measure(args.iterations, inspect_text),
        "targets_ms": {"action_p95": 10, "ordinary_text_inspection_p95": 50},
    }
    if args.artifact:
        artifact = Path(args.artifact)
        result["artifact"] = str(artifact)
        result["artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
