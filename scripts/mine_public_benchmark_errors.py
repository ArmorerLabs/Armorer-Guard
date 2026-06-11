from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter, defaultdict
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
DEFAULT_OUT = ROOT / "results" / "public_benchmark_error_mining"


def load_runner(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("armorer_sota_runner", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not import benchmark runner: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["armorer_sota_runner"] = module
    spec.loader.exec_module(module)
    return module


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open() as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mine Armorer Guard false positives/negatives from public benchmark predictions."
    )
    parser.add_argument("--runner", type=Path, default=DEFAULT_RUNNER)
    parser.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--model", default="Armorer Guard")
    parser.add_argument("--limit", type=int, default=250)
    args = parser.parse_args()

    runner = load_runner(args.runner)
    benchmarks, manifest = runner.load_public_cases(None)
    cases = {case.id: case for rows in benchmarks.values() for case in rows}
    predictions = [
        row for row in read_jsonl(args.predictions) if row.get("model") == args.model
    ]

    args.out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "prediction_file": str(args.predictions),
        "runner": str(args.runner),
        "model": args.model,
        "manifest": manifest,
        "benchmarks": {},
    }
    errors_by_benchmark: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for row in predictions:
        case = cases.get(str(row.get("case_id")))
        if case is None:
            continue
        label = int(row.get("label", 0))
        prediction = int(row.get("prediction", 0))
        kind = "true_positive" if label and prediction else "true_negative"
        if label == 1 and prediction == 0:
            kind = "false_negative"
        elif label == 0 and prediction == 1:
            kind = "false_positive"
        enriched = {
            **row,
            "error_kind": kind,
            "split": case.split,
            "text": case.text,
            "context": case.context,
        }
        if kind in {"false_positive", "false_negative"}:
            errors_by_benchmark[case.benchmark].append(enriched)

    for benchmark, rows in errors_by_benchmark.items():
        counts = Counter(row["error_kind"] for row in rows)
        split_counts = Counter(row["split"] for row in rows)
        category_counts = Counter(row.get("category", "") for row in rows)
        score_buckets = Counter(
            f"{int(float(row.get('score', 0.0)) * 10) / 10:.1f}" for row in rows
        )
        summary["benchmarks"][benchmark] = {
            "errors": len(rows),
            "false_positives": counts.get("false_positive", 0),
            "false_negatives": counts.get("false_negative", 0),
            "splits": dict(split_counts),
            "top_categories": category_counts.most_common(20),
            "score_buckets": dict(score_buckets),
        }
        out_path = args.out_dir / f"{benchmark}_errors.jsonl"
        with out_path.open("w") as handle:
            for row in rows[: args.limit]:
                handle.write(json.dumps(row, sort_keys=True) + "\n")

    (args.out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(summary["benchmarks"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
