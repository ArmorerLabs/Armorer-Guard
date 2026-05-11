#!/usr/bin/env bash
set -euo pipefail

REPO_ID="${ARMORER_GUARD_MODEL_REPO:-armorer-labs/armorer-guard-semantic-classifier}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODEL_DIR="${ROOT}/models/semantic_classifier"

if ! command -v hf >/dev/null 2>&1; then
  echo "error: hf CLI is required. Install it from https://huggingface.co/docs/huggingface_hub/guides/cli" >&2
  exit 1
fi

mkdir -p "${MODEL_DIR}"

hf download "${REPO_ID}" \
  --repo-type model \
  --local-dir "${MODEL_DIR}" \
  --include README.md LICENSE.md labels.json metrics.json semantic_classifier.joblib semantic_classifier.onnx semantic_classifier_native.tsv

cp "${MODEL_DIR}/semantic_classifier_native.tsv" "${ROOT}/src/semantic_classifier_native.tsv"

echo "Downloaded Armorer Guard model artifacts from ${REPO_ID}"
echo "Runtime native TSV updated at src/semantic_classifier_native.tsv"
