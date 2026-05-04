from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import joblib
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = ROOT / "models" / "semantic_experiments" / "word-sgd-onnx-t014" / "semantic_classifier.joblib"
DEFAULT_DATA = ROOT / "training" / "semantic_classifier" / "semantic_train.jsonl"
DEFAULT_BINARY = ROOT / "target" / "release" / ("armorer-guard.exe" if __import__("os").name == "nt" else "armorer-guard")


def load_texts(path: Path, limit: int) -> list[str]:
    texts = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        text = str(row.get("text") or "").strip()
        if text:
            texts.append(text)
        if len(texts) >= limit:
            break
    return texts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--threshold", type=float, default=0.80)
    parser.add_argument("--limit", type=int, default=500)
    args = parser.parse_args()

    artifact = joblib.load(args.model)
    model = artifact["model"]
    labels = list(artifact["labels"])
    texts = load_texts(args.data, args.limit)
    scores = model.predict_proba(texts)
    sklearn_predictions = [{label for label, score in zip(labels, row) if float(score) >= args.threshold} for row in scores]

    native_predictions = []
    native_scores = []
    for text in texts:
        completed = subprocess.run(
            [str(args.binary), "semantic-scores"],
            input=text,
            capture_output=True,
            text=True,
            check=True,
        )
        parsed = json.loads(completed.stdout)
        row_scores = parsed.get("scores", {})
        native_scores.append([float(row_scores.get(label, 0.0)) for label in labels])
        native_predictions.append({label for label in labels if float(row_scores.get(label, 0.0)) >= args.threshold})

    native_scores_array = np.array(native_scores)
    exact = [expected == actual for expected, actual in zip(sklearn_predictions, native_predictions)]
    label_matches = []
    for expected, actual in zip(sklearn_predictions, native_predictions):
        for label in labels:
            label_matches.append((label in expected) == (label in actual))

    mismatches = [
        {"text": text, "sklearn": sorted(expected), "native": sorted(actual)}
        for text, expected, actual, ok in zip(texts, sklearn_predictions, native_predictions, exact)
        if not ok
    ][:10]
    report = {
        "texts": len(texts),
        "exact_prediction_match": float(np.mean(exact)) if exact else 1.0,
        "label_prediction_match": float(np.mean(label_matches)) if label_matches else 1.0,
        "max_score_delta": float(np.abs(scores - native_scores_array).max()) if texts else 0.0,
        "mismatches": mismatches,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["label_prediction_match"] < 0.99:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
