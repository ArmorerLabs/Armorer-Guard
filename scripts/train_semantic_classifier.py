from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import perf_counter

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
from sklearn.multiclass import OneVsRestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MultiLabelBinarizer


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "training" / "semantic_classifier" / "semantic_train.jsonl"
DEFAULT_OUT = ROOT / "models" / "semantic_classifier"
LABELS = [
    "prompt_injection",
    "system_prompt_extraction",
    "data_exfiltration",
    "sensitive_data_request",
    "safety_bypass",
    "destructive_command",
]


def load_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def split_rows(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    train = [row for row in rows if row.get("training_split") == "train" and row.get("can_train") is True]
    validation = [row for row in rows if row.get("training_split") == "validation" and row.get("can_train") is True]
    if not train or not validation:
        raise SystemExit("training data must include train and validation rows with can_train=true")
    return train, validation


def fit_model(train: list[dict]) -> tuple[Pipeline, MultiLabelBinarizer]:
    mlb = MultiLabelBinarizer(classes=LABELS)
    y = mlb.fit_transform([row.get("labels", []) for row in train])
    model = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 4),
                    min_df=2,
                    lowercase=True,
                    strip_accents="unicode",
                    max_features=30_000,
                ),
            ),
            (
                "classifier",
                OneVsRestClassifier(
                    SGDClassifier(
                        loss="log_loss",
                        alpha=0.00002,
                        class_weight="balanced",
                        max_iter=80,
                        random_state=2488,
                        tol=1e-4,
                    )
                ),
            ),
        ]
    )
    model.fit([row["text"] for row in train], y)
    return model, mlb


def predict(model: Pipeline, texts: list[str], threshold: float) -> np.ndarray:
    scores = model.predict_proba(texts)
    return (scores >= threshold).astype(int)


def evaluate(model: Pipeline, mlb: MultiLabelBinarizer, validation: list[dict], threshold: float) -> dict:
    texts = [row["text"] for row in validation]
    y_true = mlb.transform([row.get("labels", []) for row in validation])
    started = perf_counter()
    y_pred = predict(model, texts, threshold)
    elapsed_ms = (perf_counter() - started) * 1000.0
    per_item_ms = elapsed_ms / max(1, len(texts))
    exact_match = float((y_true == y_pred).all(axis=1).mean())
    samples = []
    for row, truth, pred in zip(validation[:20], y_true[:20], y_pred[:20]):
        samples.append(
            {
                "id": row["id"],
                "truth": list(mlb.inverse_transform(truth.reshape(1, -1))[0]),
                "predicted": list(mlb.inverse_transform(pred.reshape(1, -1))[0]),
            }
        )
    return {
        "threshold": threshold,
        "validation_rows": len(validation),
        "exact_match": exact_match,
        "micro_precision": float(precision_score(y_true, y_pred, average="micro", zero_division=0)),
        "micro_recall": float(recall_score(y_true, y_pred, average="micro", zero_division=0)),
        "micro_f1": float(f1_score(y_true, y_pred, average="micro", zero_division=0)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "avg_latency_ms": per_item_ms,
        "classification_report": classification_report(
            y_true,
            y_pred,
            target_names=list(mlb.classes_),
            output_dict=True,
            zero_division=0,
        ),
        "sample_predictions": samples,
    }


def export_onnx(model: Pipeline, out_path: Path) -> bool:
    try:
        from skl2onnx import to_onnx
        from skl2onnx.common.data_types import StringTensorType
    except Exception as exc:
        print(f"skipping ONNX export: {exc}")
        return False
    onx = to_onnx(
        model,
        initial_types=[("text", StringTensorType([None, 1]))],
        target_opset=15,
    )
    out_path.write_bytes(onx.SerializeToString())
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--threshold", type=float, default=0.42)
    args = parser.parse_args()

    rows = load_rows(args.data)
    forbidden = [row["id"] for row in rows if row.get("can_train") is not True]
    if forbidden:
        raise SystemExit(f"found non-trainable rows in training data: {forbidden[:5]}")

    train, validation = split_rows(rows)
    model, mlb = fit_model(train)
    metrics = evaluate(model, mlb, validation, args.threshold)

    args.out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "labels": list(mlb.classes_), "threshold": args.threshold}, args.out / "semantic_classifier.joblib")
    (args.out / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True))
    (args.out / "labels.json").write_text(json.dumps(list(mlb.classes_), indent=2))
    exported = export_onnx(model, args.out / "semantic_classifier.onnx")
    print(json.dumps({"train_rows": len(train), "validation_rows": len(validation), "onnx_exported": exported, **metrics}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
