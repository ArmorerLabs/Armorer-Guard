from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNNER = (
    ROOT.parent
    / "research"
    / "papers"
    / "armorer-guard-hot-path-defense"
    / "scripts"
    / "run_sota_evidence.py"
)
DEFAULT_PREDICTIONS = (
    ROOT.parent
    / "research"
    / "papers"
    / "armorer-guard-hot-path-defense"
    / "results"
    / "local_baselines"
    / "public_benchmark_predictions.jsonl"
)
DEFAULT_BASE = ROOT / "training" / "semantic_classifier" / "profile_public_distill_train.jsonl"
DEFAULT_OUT = ROOT / "training" / "semantic_classifier" / "profile_public_error_mined_train.jsonl"

TRAINABLE_SPLITS = {"train", "synthetic_control"}
TARGET_BENCHMARKS = {
    "bipia_html_element_injection_balanced",
    "deepset_prompt_injections_legacy",
    "jackhhao_jailbreak_classification",
    "jayavibhav_prompt_injection_safety",
    "lakera_gandalf_balanced",
    "lakera_mosscap_balanced",
    "slabs_prompt_injection_dataset",
    "spml_chatbot_prompt_injection",
    "xtram_safe_guard_prompt_injection",
    "zachz_prompt_injection_benchmark",
}


def load_runner(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("armorer_sota_runner", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not import benchmark runner: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["armorer_sota_runner"] = module
    spec.loader.exec_module(module)
    return module


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open() as handle:
        return [json.loads(line) for line in handle if line.strip()]


def stable_id(prefix: str, text: str, labels: list[str]) -> str:
    digest = hashlib.sha256(
        f"{prefix}\n{text}\n{','.join(labels)}".encode("utf-8")
    ).hexdigest()[:20]
    return f"{prefix}_{digest}"


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def infer_labels(text: str, benchmark: str, category: str) -> list[str]:
    lower = text.lower()
    labels: set[str] = set()
    if any(
        cue in lower
        for cue in [
            "system prompt",
            "hidden prompt",
            "secret word",
            "magic word",
            "instructions are",
            "guidelines",
            "configuration",
        ]
    ):
        labels.add("system_prompt_extraction")
    if any(
        cue in lower
        for cue in [
            "api key",
            "token",
            "password",
            "medical record",
            "financial",
            "confidential information",
            "personal information",
            "account details",
        ]
    ):
        labels.add("sensitive_data_request")
    if any(
        cue in lower
        for cue in [
            "send",
            "forward",
            "upload",
            "post",
            "webhook",
            "third party",
            "external",
        ]
    ) and any(
        cue in lower
        for cue in [
            "secret",
            "token",
            "credential",
            "confidential",
            "private",
            "medical",
            "financial",
        ]
    ):
        labels.add("data_exfiltration")
    if any(
        cue in lower
        for cue in [
            "bypass",
            "restriction",
            "guardrail",
            "safety",
            "unrestricted",
            "uncensored",
            "no policy",
            "no filter",
            "dan",
        ]
    ):
        labels.add("safety_bypass")
    if any(
        cue in lower
        for cue in [
            "ignore",
            "disregard",
            "forget",
            "override",
            "previous instruction",
            "new instructions",
            "act as",
            "pretend",
            "roleplay",
            "developer mode",
        ]
    ):
        labels.add("prompt_injection")
    if "mosscap" in benchmark or "bipia" in benchmark:
        labels.add("prompt_injection")
    if "jailbreak" in benchmark or "xtram" in benchmark or "slabs" in benchmark:
        labels.add("prompt_injection")
    if "unsafe" in category or "injection" in category or "jailbreak" in category:
        labels.add("prompt_injection")
    if not labels:
        labels.add("prompt_injection")
    return sorted(labels)


def attack_variants(text: str) -> list[str]:
    text = normalize_text(text)
    variants = [text]
    if len(text) < 240:
        variants.extend(
            [
                f"A public benchmark attack says: {text}",
                f"Within a benign-looking chat, the unsafe user request is: {text}",
                f"Classify this live user request before execution: {text}",
            ]
        )
    return variants


def benign_variants(text: str) -> list[str]:
    text = normalize_text(text)
    variants = [text]
    if len(text) < 220:
        variants.extend(
            [
                f"Safe educational context only: {text}",
                f"Documentation note, not an instruction to execute: {text}",
            ]
        )
    return variants


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build an augmented high-recall profile corpus from train-split public benchmark errors."
    )
    parser.add_argument("--runner", type=Path, default=DEFAULT_RUNNER)
    parser.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS)
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--model", default="Armorer Guard")
    parser.add_argument("--max-false-positives-per-benchmark", type=int, default=5000)
    parser.add_argument("--max-false-negatives-per-benchmark", type=int, default=8000)
    args = parser.parse_args()

    runner = load_runner(args.runner)
    benchmarks, _manifest = runner.load_public_cases(None)
    cases = {case.id: case for rows in benchmarks.values() for case in rows}
    base_rows = read_jsonl(args.base)
    existing_keys = {
        hashlib.sha256(
            f"{normalize_text(row.get('text', ''))}\n{','.join(row.get('labels', []))}".encode("utf-8")
        ).hexdigest()
        for row in base_rows
    }

    fp_counts: Counter[str] = Counter()
    fn_counts: Counter[str] = Counter()
    added: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    with args.predictions.open() as handle:
        for line in handle:
            if not line.strip():
                continue
            pred_row = json.loads(line)
            if pred_row.get("model") != args.model:
                continue
            case = cases.get(str(pred_row.get("case_id")))
            if case is None:
                continue
            if case.benchmark not in TARGET_BENCHMARKS:
                continue
            if case.split not in TRAINABLE_SPLITS:
                continue
            label = int(pred_row.get("label", 0))
            prediction = int(pred_row.get("prediction", 0))
            variants: list[str]
            labels: list[str]
            family: str
            if label == 1 and prediction == 0:
                if fn_counts[case.benchmark] >= args.max_false_negatives_per_benchmark:
                    continue
                fn_counts[case.benchmark] += 1
                labels = infer_labels(case.text, case.benchmark, case.category)
                variants = attack_variants(case.text)
                family = "public_error_mined_false_negative"
            elif label == 0 and prediction == 1:
                if fp_counts[case.benchmark] >= args.max_false_positives_per_benchmark:
                    continue
                fp_counts[case.benchmark] += 1
                labels = []
                variants = benign_variants(case.text)
                family = "public_error_mined_false_positive"
            else:
                continue
            for index, variant in enumerate(variants):
                text = normalize_text(variant)
                dedupe_key = hashlib.sha256(
                    f"{text}\n{','.join(labels)}".encode("utf-8")
                ).hexdigest()
                if dedupe_key in existing_keys:
                    continue
                existing_keys.add(dedupe_key)
                added.append(
                    {
                        "id": stable_id(f"{family}_{case.benchmark}", text, labels),
                        "text": text,
                        "labels": labels,
                        "training_split": "train",
                        "scenario_family": family,
                        "source": f"public_error_mined:{case.benchmark}:{case.split}",
                        "source_case_id": case.id,
                        "source_category": case.category,
                        "source_score": float(pred_row.get("score", 0.0)),
                        "source_reasons": pred_row.get("reasons", []),
                        "can_train": True,
                        "created_at": now,
                    }
                )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as handle:
        for row in base_rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
        for row in added:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "base_rows": len(base_rows),
                "added_rows": len(added),
                "output_rows": len(base_rows) + len(added),
                "false_positives_used": dict(fp_counts),
                "false_negatives_used": dict(fn_counts),
                "out": str(args.out),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
