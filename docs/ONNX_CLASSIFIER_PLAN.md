# ONNX Semantic Classifier Plan

## Goal

Add a local ONNX-backed semantic classifier to Armorer Guard without replacing
the deterministic lanes that already work well.

The classifier should improve non-token threat detection for:

- prompt injection
- system prompt extraction
- data exfiltration
- sensitive data requests
- safety bypass
- destructive commands
- benign near misses

It must stay local-first. No network calls are allowed at runtime.

## Current Baseline

Today the semantic lane is lexical/rule based and runs entirely in Rust. The
similarity lane uses Jaccard token overlap against Armorer-owned development
exemplars from `src/dev_exemplars.tsv`.

The ONNX classifier should become an additional lane:

```text
credential_lane
semantic_rule_lane
semantic_onnx_lane
similarity_lane
policy_lane
aggregation
```

If the ONNX model is missing, fails to load, or exceeds its runtime budget,
Guard must degrade to the current deterministic behavior.

## Training Data Rules

Do not train on release eval rows.

Allowed training data:

- Armorer-owned development examples marked `can_train=true`
- synthetic training prompts generated specifically for training
- explicitly licensed third-party datasets after license/provenance review
- rewritten failures after a release decision is complete, with wording changed
  enough to avoid memorizing holdout text

Forbidden training data:

- `regression` eval text
- `hard` eval text
- `holdout` eval text
- exact copied payloads from third-party corpora without license clearance
- user secrets, local logs, private chat transcripts, or production messages

Every training row should include:

- `id`
- `text`
- `labels`
- `split`
- `provenance`
- `generator_version`
- `can_train`
- `created_at`

## Recommended First Model

Start with a small multi-label text classifier.

Target labels:

```text
benign
prompt_injection
system_prompt_extraction
data_exfiltration
sensitive_data_request
safety_bypass
destructive_command
```

The first production candidate should prioritize latency and portability over
maximum benchmark score.

Suggested target:

- model family: small distilled transformer or compact sentence classifier
- export format: ONNX
- quantization: int8 if quality stays acceptable
- runtime budget: p50 under 10ms, p95 under 25ms on laptop CPU
- fallback: deterministic rules if ONNX unavailable

## Training Flow

1. Build a private training dataset from `can_train=true` development data.
2. Generate synthetic variants for each class.
3. Add benign near-miss examples that mention attacks without requesting them.
4. Split into train and validation sets by scenario family, not random rows.
5. Train a multi-label classifier.
6. Export to ONNX.
7. Quantize the ONNX model.
8. Run local validation against development validation data.
9. Run `armorer-guard-evals` on `regression`.
10. Run `hard` as a stress suite.
11. Run `holdout` only for release-candidate validation.

## Why Split By Scenario Family

Random row splits can leak near-duplicates into validation, creating inflated
scores. Instead, group related prompts by generator template, source, or attack
family. Hold entire families out of training validation when possible.

This tests whether the classifier generalizes rather than memorizes wording.

## Acceptance Criteria For First Prototype

The ONNX lane is worth merging only if it improves semantic threats without
hurting credential behavior.

Minimum prototype bar:

- credential capture unchanged on regression
- benign false-positive rate below 5 percent on regression
- non-token expected-block recall improves over rule baseline
- prompt injection recall improves over rule baseline
- data exfiltration recall improves over rule baseline
- p95 classifier latency under 25ms in non-model fallback mode unchanged
- deterministic fallback remains available and tested

## Rust Runtime Integration

The Rust binary should own production inference.

Planned implementation shape:

```text
src/onnx_classifier.rs
  load model
  tokenize input
  run inference
  map logits/probabilities to labels
  return category confidences

src/main.rs
  call semantic rules
  call ONNX classifier if enabled and available
  merge category confidences
  apply policy lane
```

The public Python package should still shell out to the Rust binary. It should
not contain private model logic.

## Runtime Configuration

Default behavior should be conservative:

```text
ARMORER_GUARD_ONNX=auto
```

Modes:

- `off`: never load ONNX
- `auto`: load if bundled and compatible, otherwise fallback
- `required`: fail inspection if the model cannot load

Production default should be `auto`.

## Confidence Aggregation

Rules and model scores should both contribute to the final reasons.

Suggested policy:

- credential lane remains deterministic and independent
- policy lane can block regardless of model score
- ONNX label probability over threshold emits the matching semantic reason
- when rules and ONNX agree, confidence increases
- when they disagree, keep the higher confidence but preserve lane metadata for
  debugging

Example:

```json
{
  "reasons": ["semantic:prompt_injection"],
  "confidence": 0.91,
  "lane_scores": {
    "semantic_rules": 0.88,
    "semantic_onnx": 0.91
  }
}
```

## Evaluation Tracking

Add experiments in `armorer-guard-evals`:

- `rules-baseline`
- `onnx-semantic-v1`
- `rules-plus-onnx-v1`
- `rules-plus-onnx-quantized-v1`

Track:

- accuracy
- precision
- recall
- F1
- false positives
- false negatives
- p50 latency
- p95 latency
- max latency
- per-category metrics
- generalization delta between dev/regression/hard/holdout

## Prototype Status

Branch `codex/onnx-semantic-classifier` includes the first training scaffold:

- `scripts/generate_semantic_training_data.py`
- `scripts/train_semantic_classifier.py`
- `scripts/evaluate_semantic_classifier.py`
- `training/semantic_classifier/semantic_train.jsonl`
- `models/semantic_classifier/semantic_classifier.joblib`
- `models/semantic_classifier/metrics.json`
- `models/semantic_classifier/eval_regression.json`
- `models/semantic_classifier/eval_hard.json`

The current prototype is a local scikit-learn multi-label character n-gram
classifier. It is not exported to ONNX yet because the local environment is
missing `onnx` and `skl2onnx`.

Current generated training corpus:

- 8,935 rows
- 7,670 train rows
- 1,265 validation rows
- all rows are Armorer-owned synthetic or explicit `dev_exemplars.tsv`
- all rows are separate from `armorer-guard-evals`
- all rows have `can_train=true`

Current standalone classifier eval:

```text
regression:
  cases: 382
  accuracy: 78.5%
  block precision: 89.5%
  block recall: 78.9%
  micro F1: 76.8%
  avg latency: 0.04ms

hard:
  cases: 5926
  accuracy: 50.7%
  block precision: 80.3%
  block recall: 23.4%
  micro F1: 17.3%
  avg latency: 0.11ms
```

Interpretation:

- The prototype is fast.
- The prototype is not strong enough to replace the rule/policy lanes.
- The intended production shape remains hybrid: deterministic lanes plus ONNX
  signal aggregation.
- Hard split recall is still weak, especially for broad third-party prompt
  injection patterns. More diverse trainable data is required before the ONNX
  lane is useful as a high-confidence standalone detector.

## Open Questions

- Which small model architecture gives the best latency/recall tradeoff?
- Should tokenizer assets be bundled into the closed binary package or loaded
  from a model directory?
- Should ONNX be enabled for all platforms immediately or staged per platform?
- How should we expose per-lane scores without changing the current public API?
- What is the minimum training corpus size before the classifier beats rules on
  hard non-token cases?
