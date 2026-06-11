from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = ROOT / "models" / "semantic_experiments" / "word-sgd-onnx-t014" / "semantic_classifier.joblib"
DEFAULT_OUT = ROOT / "src" / "semantic_classifier_native.tsv"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--threshold", type=float, default=0.80)
    parser.add_argument("--model-name", default="word-sgd-native-v1")
    args = parser.parse_args()

    artifact = joblib.load(args.model)
    model = artifact["model"]
    labels = list(artifact["labels"])
    vectorizer = model.named_steps["tfidf"]
    classifier = model.named_steps["classifier"]

    terms_by_index = sorted(vectorizer.vocabulary_.items(), key=lambda item: item[1])
    intercepts = [float(estimator.intercept_[0]) for estimator in classifier.estimators_]
    coefficients = [estimator.coef_[0].astype(float).tolist() for estimator in classifier.estimators_]

    model_path = args.model.resolve()
    try:
        source_model = str(model_path.relative_to(ROOT))
    except ValueError:
        source_model = str(model_path)

    metadata = {
        "format": "armorer_native_linear_tfidf_v1",
        "source_model": source_model,
        "model_name": args.model_name,
        "threshold": args.threshold,
        "labels": labels,
        "analyzer": vectorizer.analyzer,
        "ngram_range": list(vectorizer.ngram_range),
        "lowercase": bool(vectorizer.lowercase),
        "token_pattern": vectorizer.token_pattern,
        "norm": vectorizer.norm,
        "use_idf": bool(vectorizer.use_idf),
        "smooth_idf": bool(vectorizer.smooth_idf),
        "sublinear_tf": bool(vectorizer.sublinear_tf),
        "intercepts": intercepts,
        "feature_count": len(terms_by_index),
    }

    lines = [
        "# " + json.dumps(metadata, sort_keys=True, separators=(",", ":")),
        "# term\tidf\tcoef_prompt_injection\tcoef_system_prompt_extraction\tcoef_data_exfiltration\tcoef_sensitive_data_request\tcoef_safety_bypass\tcoef_destructive_command",
    ]
    for term, index in terms_by_index:
        values = [term, f"{float(vectorizer.idf_[index]):.12g}"]
        values.extend(f"{coefficients[label_index][index]:.12g}" for label_index in range(len(labels)))
        lines.append("\t".join(values))

    args.out.write_text("\n".join(lines) + "\n")
    print(json.dumps(metadata, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
