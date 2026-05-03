from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import onnxruntime as ort


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--split", default="hard")
    parser.add_argument("--batch-size", type=int, default=256)
    args = parser.parse_args()

    artifact = joblib.load(args.model_dir / "semantic_classifier.joblib")
    model = artifact["model"]
    threshold = float(artifact.get("threshold", 0.42))
    texts = [case["input"] for case in load_cases(args.cases, args.split)]

    sklearn_scores = model.predict_proba(texts)
    sklearn_pred = sklearn_scores >= threshold

    session = ort.InferenceSession(str(args.model_dir / "semantic_classifier.onnx"), providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    onnx_scores = []
    for start in range(0, len(texts), args.batch_size):
        batch = np.array(texts[start : start + args.batch_size], dtype=object).reshape((-1, 1))
        outputs = session.run(None, {input_name: batch})
        probabilities = outputs[1]
        if isinstance(probabilities, list):
            scores = np.zeros((len(probabilities), sklearn_scores.shape[1]), dtype=float)
            for row_index, row_scores in enumerate(probabilities):
                for label_index, score in row_scores.items():
                    scores[row_index, int(label_index)] = float(score)
        else:
            scores = np.asarray(probabilities, dtype=float)
        onnx_scores.append(scores)

    onnx_scores_array = np.vstack(onnx_scores) if onnx_scores else np.zeros_like(sklearn_scores)
    onnx_pred = onnx_scores_array >= threshold
    metrics = {
        "model_dir": str(args.model_dir),
        "split": args.split,
        "threshold": threshold,
        "cases": len(texts),
        "exact_prediction_match": float((sklearn_pred == onnx_pred).all(axis=1).mean()) if texts else 1.0,
        "label_prediction_match": float((sklearn_pred == onnx_pred).mean()) if texts else 1.0,
        "max_score_delta": float(np.abs(sklearn_scores - onnx_scores_array).max()) if texts else 0.0,
    }
    print(json.dumps(metrics, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
