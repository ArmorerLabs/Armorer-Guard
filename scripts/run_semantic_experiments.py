from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "training" / "semantic_classifier" / "semantic_train.jsonl"
DEFAULT_CASES = ROOT.parent / "armorer-guard-evals" / "data" / "guard_cases.jsonl"
DEFAULT_OUT = ROOT / "models" / "semantic_experiments"
EVAL_REPO_MARKER = "armorer-guard-evals"


EXPERIMENTS = [
    {
        "name": "word-sgd-onnx-t042",
        "description": "ONNX-exportable word 1-2gram SGD baseline.",
        "args": [
            "--analyzer",
            "word",
            "--ngram-min",
            "1",
            "--ngram-max",
            "2",
            "--max-features",
            "50000",
            "--model-kind",
            "sgd",
            "--strip-accents",
            "none",
            "--threshold",
            "0.42",
        ],
    },
    {
        "name": "word-sgd-onnx-t030",
        "description": "Lower threshold for better recall while staying ONNX-exportable.",
        "args": [
            "--analyzer",
            "word",
            "--ngram-min",
            "1",
            "--ngram-max",
            "2",
            "--max-features",
            "50000",
            "--model-kind",
            "sgd",
            "--strip-accents",
            "none",
            "--threshold",
            "0.30",
        ],
    },
    {
        "name": "word-sgd-onnx-ngrams13-t035",
        "description": "Word 1-3grams with a recall-oriented threshold.",
        "args": [
            "--analyzer",
            "word",
            "--ngram-min",
            "1",
            "--ngram-max",
            "3",
            "--max-features",
            "80000",
            "--model-kind",
            "sgd",
            "--strip-accents",
            "none",
            "--threshold",
            "0.35",
        ],
    },
    {
        "name": "char-sgd-t030",
        "description": "Character ngram local model; not ONNX-exportable with current converter.",
        "args": [
            "--analyzer",
            "char_wb",
            "--ngram-min",
            "3",
            "--ngram-max",
            "4",
            "--max-features",
            "30000",
            "--model-kind",
            "sgd",
            "--strip-accents",
            "unicode",
            "--threshold",
            "0.30",
        ],
    },
    {
        "name": "word-logreg-onnx-t030",
        "description": "Logistic regression comparison model with ONNX-exportable word features.",
        "args": [
            "--analyzer",
            "word",
            "--ngram-min",
            "1",
            "--ngram-max",
            "2",
            "--max-features",
            "50000",
            "--model-kind",
            "logreg",
            "--strip-accents",
            "none",
            "--threshold",
            "0.30",
        ],
    },
]


def run_json(command: list[str]) -> dict:
    completed = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    output = completed.stdout.strip()
    if not output:
        raise SystemExit(f"command produced no JSON output: {' '.join(command)}")
    start = output.rfind("\n{")
    json_text = output[start + 1 :] if start >= 0 else output
    return json.loads(json_text)


def fail_if_eval_training_data(data_path: Path) -> None:
    resolved = data_path.resolve()
    if EVAL_REPO_MARKER in resolved.parts:
        raise SystemExit(f"refusing to train from eval repository path: {resolved}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--splits", nargs="+", default=["regression", "hard"])
    parser.add_argument("--only", nargs="*", default=None)
    args = parser.parse_args()

    fail_if_eval_training_data(args.data)
    args.out.mkdir(parents=True, exist_ok=True)

    selected = [exp for exp in EXPERIMENTS if not args.only or exp["name"] in set(args.only)]
    if not selected:
        raise SystemExit("no experiments selected")

    summary = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "training_data": str(args.data),
        "eval_cases": str(args.cases),
        "experiments": [],
    }
    for experiment in selected:
        exp_dir = args.out / experiment["name"]
        train_command = [
            sys.executable,
            "scripts/train_semantic_classifier.py",
            "--data",
            str(args.data),
            "--out",
            str(exp_dir),
            *experiment["args"],
        ]
        train_metrics = run_json(train_command)
        evals: dict[str, dict] = {}
        for split in args.splits:
            eval_metrics = run_json(
                [
                    sys.executable,
                    "scripts/evaluate_semantic_classifier.py",
                    "--model",
                    str(exp_dir / "semantic_classifier.joblib"),
                    "--cases",
                    str(args.cases),
                    "--split",
                    split,
                ]
            )
            (exp_dir / f"eval_{split}.json").write_text(json.dumps(eval_metrics, indent=2, sort_keys=True))
            evals[split] = eval_metrics

        record = {
            "name": experiment["name"],
            "description": experiment["description"],
            "train": train_metrics,
            "evals": evals,
        }
        (exp_dir / "experiment.json").write_text(json.dumps(record, indent=2, sort_keys=True))
        summary["experiments"].append(record)

    summary["finished_at"] = datetime.now(timezone.utc).isoformat()
    summary_path = args.out / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True))
    print(json.dumps({"summary": str(summary_path), "experiments": [exp["name"] for exp in selected]}, indent=2))


if __name__ == "__main__":
    main()
