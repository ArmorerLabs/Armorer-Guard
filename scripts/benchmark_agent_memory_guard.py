#!/usr/bin/env python3
"""Run OWASP Agent Memory Guard and Armorer Guard on the same upstream corpus.

The corpus stays in the upstream Apache-2.0 checkout. This script imports it at
runtime so Armorer does not silently fork or alter the OWASP benchmark cases.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class Score:
    total: int = 0
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    latencies_us: list[float] | None = None
    misses: list[str] | None = None

    def finish(self) -> dict[str, Any]:
        latencies = self.latencies_us or []
        precision_denominator = self.true_positives + self.false_positives
        recall_denominator = self.true_positives + self.false_negatives
        precision = self.true_positives / precision_denominator if precision_denominator else 0.0
        recall = self.true_positives / recall_denominator if recall_denominator else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        result = asdict(self)
        result.update(
            precision=precision,
            recall=recall,
            f1=f1,
            median_latency_us=statistics.median(latencies) if latencies else None,
            p95_latency_us=(
                sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)]
                if latencies
                else None
            ),
        )
        result.pop("latencies_us")
        return result


def load_upstream_benchmark(repo: Path):
    sys.path.insert(0, str(repo / "src"))
    path = repo / "benchmarks" / "security_benchmark.py"
    spec = importlib.util.spec_from_file_location("owasp_amg_security_benchmark", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def content_ref(text: str) -> str:
    return "content/sha256:" + hashlib.sha256(text.encode()).hexdigest()


def post_unix(socket_path: Path, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    request = (
        f"POST {path} HTTP/1.1\r\nHost: localhost\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(socket_path))
        client.sendall(request)
        response = bytearray()
        while chunk := client.recv(65536):
            response.extend(chunk)
    head, raw_body = bytes(response).split(b"\r\n\r\n", 1)
    status = int(head.split(b" ", 2)[1])
    parsed = json.loads(raw_body)
    if status != 200:
        raise RuntimeError(f"Guard returned HTTP {status}: {parsed}")
    return parsed


def wait_ready(socket_path: Path, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read().decode() if process.stderr else ""
            raise RuntimeError(f"Guard sidecar exited before readiness: {stderr}")
        if socket_path.exists():
            return
        time.sleep(0.02)
    raise RuntimeError("Guard sidecar did not create its socket within 10 seconds")


def score_armorer(corpus: list[Any], socket_path: Path) -> dict[str, Any]:
    score = Score(latencies_us=[], misses=[])
    for index, case in enumerate(corpus):
        text = case.value if isinstance(case.value, str) else json.dumps(case.value)
        namespace, separator, key = case.key.partition(".")
        if not separator:
            namespace, key = "default", namespace
        payload = {
            "schema_version": "armorer-guard-content-evaluation/v1",
            "request_id": f"benchmark/{index}",
            "trace_id": f"trace/benchmark/{index}",
            "session_id": "session/owasp-amg-head-to-head",
            "subject": {
                "agent_id": "example-agent",
                "identity_id": "spiffe://example/agents/example-agent",
                "tenant_id": "tenant/example",
            },
            "purpose": "memory-integrity-benchmark",
            "segments": [{
                "content_ref": content_ref(text),
                "origin": "agent_memory_write",
                "principal_id": "agent/example-agent",
                "tenant_id": "tenant/example",
                "trust": "untrusted",
                "data_classes": [],
                "instruction_authority": "none",
                "retention": "local_only",
                "text": text,
            }],
            "memory_target": {"namespace": namespace, "key": key},
        }
        started = time.perf_counter_ns()
        decision = post_unix(socket_path, "/v1/memory/write/evaluate", payload)
        score.latencies_us.append((time.perf_counter_ns() - started) / 1000)
        detected = decision["effect"] not in ("allow_trusted_instruction", "allow_untrusted_data")
        score.total += 1
        if case.should_detect and detected:
            score.true_positives += 1
        elif not case.should_detect and not detected:
            score.true_negatives += 1
        elif case.should_detect:
            score.false_negatives += 1
            score.misses.append(case.description)
        else:
            score.false_positives += 1
            score.misses.append(case.description)
    return score.finish()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--amg-repo", type=Path, required=True)
    parser.add_argument("--guard-bin", type=Path, default=Path("target/release/armorer-guard"))
    parser.add_argument("--manifest", type=Path, default=Path("fixtures/runtime-agent-manifest.json"))
    parser.add_argument("--policy", type=Path, default=Path("fixtures/runtime-policy.json"))
    parser.add_argument("--key", type=Path, default=Path("fixtures/runtime-delegation.key"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    guard_bin = (root / args.guard_bin).resolve() if not args.guard_bin.is_absolute() else args.guard_bin
    manifest = (root / args.manifest).resolve() if not args.manifest.is_absolute() else args.manifest
    policy = (root / args.policy).resolve() if not args.policy.is_absolute() else args.policy
    key = (root / args.key).resolve() if not args.key.is_absolute() else args.key
    upstream_repo = args.amg_repo.resolve()
    upstream = load_upstream_benchmark(upstream_repo)
    upstream_revision = subprocess.run(
        ["git", "-C", str(upstream_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    guard_version = json.loads(
        subprocess.run(
            [str(guard_bin), "version"], check=True, capture_output=True, text=True
        ).stdout
    )["version"]
    upstream_result = upstream.run_benchmark()
    owasp = {
        "total": upstream_result.total,
        "true_positives": upstream_result.true_positives,
        "true_negatives": upstream_result.true_negatives,
        "false_positives": upstream_result.false_positives,
        "false_negatives": upstream_result.false_negatives,
        "precision": upstream_result.precision,
        "recall": upstream_result.recall,
        "f1": upstream_result.f1_score,
        "median_latency_us": statistics.median(upstream_result.latencies_us),
        "p95_latency_us": sorted(upstream_result.latencies_us)[max(0, int(len(upstream_result.latencies_us) * 0.95) - 1)],
        "misses": [item["description"] for item in upstream_result.details if item["classification"] in ("FN", "FP")],
    }

    with tempfile.TemporaryDirectory(prefix="armorer-amg-benchmark-") as temporary:
        temp = Path(temporary)
        socket_path = temp / "guard.sock"
        command = [
            str(guard_bin), "serve", "--config", str(manifest), "--socket", str(socket_path),
            "--data-dir", str(temp / "data"), "--policy", str(policy),
            "--delegation-key-file", str(key), "--policy-verifier-key-file", str(key),
            "--gateway-key-file", str(key), "--approval-verifier-key-file", str(key),
            "--evidence-encryption-key-file", str(key),
            "--evidence-authorization-key-file", str(key),
        ]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            wait_ready(socket_path, process)
            armorer = score_armorer(upstream.ATTACK_CORPUS, socket_path)
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    report = {
        "schema_version": "armorer-guard-head-to-head-benchmark/v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus_source": f"https://github.com/OWASP/www-project-agent-memory-guard/blob/{upstream_revision}/benchmarks/security_benchmark.py",
        "owasp_agent_memory_guard_revision": upstream_revision,
        "armorer_guard_version": guard_version,
        "corpus_cases": len(upstream.ATTACK_CORPUS),
        "owasp_agent_memory_guard": owasp,
        "armorer_guard": armorer,
        "latency_note": "AMG measures an in-process write; Armorer measures a Unix-socket request, inspection, provenance, encrypted evidence, and telemetry.",
    }
    encoded = json.dumps(report, indent=2, sort_keys=True)
    print(encoded)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
