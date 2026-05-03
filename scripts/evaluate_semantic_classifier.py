from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from time import perf_counter

import joblib
import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score


DEFAULT_MODEL = Path(__file__).resolve().parents[1] / "models" / "semantic_classifier" / "semantic_classifier.joblib"
LABELS = [
    "prompt_injection",
    "system_prompt_extraction",
    "data_exfiltration",
    "sensitive_data_request",
    "safety_bypass",
    "destructive_command",
]


def load_cases(path: Path, split: str) -> list[dict]:
    rows = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("enabled", True) is False:
            continue
        if row.get("suite", "integration") != "integration":
            continue
        if split != "all" and row.get("split") != split:
            continue
        rows.append(row)
    return rows


def expected_labels(row: dict) -> list[str]:
    threat = row.get("threat_category") or row.get("category")
    if threat in LABELS:
        return [threat]
    return []


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--split", default="regression")
    parser.add_argument("--threshold", type=float, default=None)
    args = parser.parse_args()

    artifact = joblib.load(args.model)
    model = artifact["model"]
    labels = artifact["labels"]
    threshold = float(args.threshold if args.threshold is not None else artifact.get("threshold", 0.42))
    cases = load_cases(args.cases, args.split)
    texts = [case["input"] for case in cases]
    truth_sets = [set(expected_labels(case)) for case in cases]
    label_index = {label: i for i, label in enumerate(labels)}
    y_true = np.zeros((len(cases), len(labels)), dtype=int)
    for row_idx, row_labels in enumerate(truth_sets):
        for label in row_labels:
            if label in label_index:
                y_true[row_idx, label_index[label]] = 1

    started = perf_counter()
    scores = model.predict_proba(texts)
    elapsed_ms = (perf_counter() - started) * 1000.0
    y_pred = (scores >= threshold).astype(int)

    predicted_block = y_pred.sum(axis=1) > 0
    expected_block = np.array([bool(labels) for labels in truth_sets], dtype=bool)
    tp = int((predicted_block & expected_block).sum())
    fp = int((predicted_block & ~expected_block).sum())
    fn = int((~predicted_block & expected_block).sum())
    tn = int((~predicted_block & ~expected_block).sum())

    failures_by_category: Counter[str] = Counter()
    for case, expected, predicted in zip(cases, expected_block, predicted_block):
        if expected != predicted:
            failures_by_category[case.get("threat_category") or case.get("category") or "unknown"] += 1

    per_category = defaultdict(lambda: {"total": 0, "tp": 0, "fp": 0, "fn": 0})
    for case, expected, predicted in zip(cases, expected_block, predicted_block):
        category = case.get("threat_category") or case.get("category") or "unknown"
        bucket = per_category[category]
        bucket["total"] += 1
        if expected and predicted:
            bucket["tp"] += 1
        elif expected and not predicted:
            bucket["fn"] += 1
        elif not expected and predicted:
            bucket["fp"] += 1

    metrics = {
        "model": str(args.model),
        "split": args.split,
        "threshold": threshold,
        "cases": len(cases),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "accuracy": (tp + tn) / len(cases) if cases else 0.0,
        "block_precision": tp / (tp + fp) if (tp + fp) else 0.0,
        "block_recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "micro_precision": float(precision_score(y_true, y_pred, average="micro", zero_division=0)),
        "micro_recall": float(recall_score(y_true, y_pred, average="micro", zero_division=0)),
        "micro_f1": float(f1_score(y_true, y_pred, average="micro", zero_division=0)),
        "avg_latency_ms": elapsed_ms / max(1, len(cases)),
        "failures_by_category": dict(failures_by_category),
        "per_category": dict(per_category),
    }
    print(json.dumps(metrics, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
