# Armorer Guard Capabilities

This document describes what the current Guard binary does, what labels it can
emit, and what it does not claim to solve yet.

For the machine-readable source of truth, run:

```bash
armorer-guard capabilities
```

or during development:

```bash
cargo run --quiet -- capabilities
```

## Public API

Armorer consumes Guard through this stable contract:

- `inspect_input(text, context=None)`
- `inspect_output(text, context=None)`
- `sanitize_text(text)`
- `detect_credentials(text, context=None)`
- `capabilities()`

The `context` argument is optional and now feeds the policy and semantic lanes
when present. Text-only callers keep the legacy behavior.

Supported context fields:

- `eval_surface`
- `trace_stage`
- `artifact_kind`
- `policy_action`
- `policy_scope`
- `tool_name`
- `destination`
- `detection_profile`

## Output Contract

`inspect_input` and `inspect_output` return:

- `sanitized_text`
- `suspicious`
- `reasons`
- `confidence`
- `scan_id`
- `model_version`
- `learning_version`

`detect_credentials` returns either `null` or:

- `captured_value`
- `sanitized_text`
- `confidence`
- `reasons`
- `credential_type`
- `suggested_key_name`
- `flags`
- `matches`

## Credential Lane

Purpose:

- capture credentials from user setup messages
- redact sensitive values before persistence
- infer the provider type
- suggest an environment variable name

Current credential types:

- `notion`
- `github`
- `openrouter`
- `openai`
- `gemini`
- `telegram_bot`
- `generic_secret`

Stable reason:

- `detected:credential`

Redaction examples:

- GitHub tokens -> `[REDACTED_GITHUB_TOKEN]`
- Notion keys -> `[REDACTED_NOTION_KEY]`
- Gemini keys -> `[REDACTED_GEMINI_KEY]`
- Telegram bot tokens -> `[REDACTED_TELEGRAM_TOKEN]`
- assignment-style secrets -> `[REDACTED_SECRET_VALUE]`

Credential detection is deterministic and intentionally not ML-based.

## Semantic Lane

Purpose:

- identify non-token suspicious requests
- keep semantic categories separate from credential capture
- produce stable reason labels for Armorer UI, alerts, and evals

Current reason labels:

- `semantic:prompt_injection`
- `semantic:system_prompt_extraction`
- `semantic:data_exfiltration`
- `semantic:sensitive_data_request`
- `semantic:safety_bypass`
- `semantic:destructive_command`

Current behavior:

- local only
- deterministic lexical/rule scoring
- bundled Rust-native TF-IDF linear classifier, `word-sgd-native-v1`
- profile-only Rust-native char-wb fallback classifier, `char-wb-public-distill-30k-v1`
- per-category classifier thresholds
- production `agent-runtime` does not run the char-wb fallback
- profile fallback training uses public benchmark train splits plus synthetic
  benign controls and Armorer-owned hard-negative/profile data; heldout
  validation must be reported separately from full-corpus public checks
- context discounts for retrieved content, model output, and agent actions
- metadata-driven word n-gram scoring, so exported native models can use
  unigrams, bigrams, trigrams, or four-grams without Rust code changes
- bounded multi-view scanning for long or HTML-like inputs: whole input first,
  then stable head/middle/tail windows and a structural HTML view
- persistent `inspect-jsonl` mode for low-latency sidecar integrations and
  benchmark runners that should not pay process startup per scan
- no network calls

This lane is still intentionally lightweight. The next major target is a
stronger local semantic model or embeddings lane that improves generalized
prompt-injection recall without training on eval rows.

## Similarity Lane

Purpose:

- catch prompts similar to known Armorer-owned attack exemplars
- provide a lightweight bridge before local embeddings are added

Current behavior:

- tokenizes text locally
- computes Jaccard similarity
- maps similar prompts to the same semantic reason labels
- indexes only `src/dev_exemplars.tsv` rows marked `can_train=true`
- never indexes eval rows from `dev`, `regression`, `hard`, or `holdout` suites

Future behavior should replace or augment this with a local vector index.

## Learning Lane

Purpose:

- adapt local enforcement from operator feedback without scanner network calls
- keep deployment-specific allow/block/review corrections outside the repo
- preserve reviewed, versioned global model releases instead of silent drift

Current behavior:

- reads local exemplars from `~/.armorer-guard/feedback/local_exemplars.tsv`
- writes feedback events to `~/.armorer-guard/feedback/events.jsonl`
- supports `ARMORER_GUARD_HOME` for tests and deployments
- accepts sanitized feedback through `armorer-guard feedback-record`
- exports reviewed rows through `armorer-guard feedback-export --reviewed-only`
- reports counts through `armorer-guard feedback-stats`

Current reason labels:

- `learning:local_allow_match`
- `learning:local_block_match`
- `learning:local_review_match`

High-risk boundary review labels:

- `review:prompt_injection`
- `review:system_prompt_extraction`
- `review:data_exfiltration`
- `review:sensitive_data_request`
- `review:safety_bypass`
- `review:destructive_command`

Safety boundaries:

- raw text is optional; sanitized excerpts and stable hashes are enough
- feedback defaults to `can_train=false`
- `can_train=true` requires `reviewed=true`
- local allow feedback cannot suppress `detected:credential`
- local allow feedback cannot suppress `policy:credential_disclosure`
- local allow feedback cannot suppress `policy:dangerous_tool_call`
- local learning does not mutate `src/semantic_classifier_native.tsv`
- local learning does not mutate `src/dev_exemplars.tsv`

## Eval Hygiene

Guard development data and release evaluation data are separate by design.

- `src/dev_exemplars.tsv` is the only current similarity source.
- Development exemplars must be Armorer-owned, provenance-tagged, and explicitly marked trainable.
- Regression, hard, and holdout eval case text must not be copied into Rust rules, similarity exemplars, classifier prompts, or model training data.
- Unreviewed local feedback must not train public models.
- Holdout failures may become visible regression cases only after the release decision, and only with rewritten wording that tests the general behavior rather than the exact prompt.

## Policy Lane

Purpose:

- mark requests that are dangerous because of intended action, not just wording
- make high-risk action categories blockable in Armorer

Current reason labels:

- `policy:credential_disclosure`
- `policy:dangerous_tool_call`

Current mappings:

- data exfiltration -> `policy:credential_disclosure`
- sensitive data request -> `policy:credential_disclosure`
- safety bypass -> `policy:dangerous_tool_call`
- destructive command -> `policy:dangerous_tool_call`

When structured context is present, the policy lane can also escalate:

- `credential_disclosure`, `outbound_transfer`, or secret-scoped sends -> data exfiltration / sensitive data request
- `system_disclosure` or `guard_internals` -> system prompt extraction
- `dangerous_tool_call`, `delete_state`, `force_push`, `drop_database`, `docker_prune`, or `sandbox_escape` -> destructive command
- `disable_guard`, `sandbox_escape`, or security-control scopes -> safety bypass

## Confidence Policy

Current confidence values are intentionally simple and stable:

- provider-specific credential capture: `0.99`
- generic secret capture: `0.75`
- credential redaction during inspection: at least `0.72`
- sensitive data request: `0.74`
- prompt injection: `0.88`
- system prompt extraction: `0.88`
- data exfiltration: `0.92`
- safety bypass: `0.91`
- destructive command: `0.94`

Classifier-only promotions use per-category thresholds:

- prompt injection: `0.78`
- system prompt extraction: `0.76`
- data exfiltration: `0.74`
- sensitive data request: `0.76`
- safety bypass: `0.76`
- destructive command: `0.72`

Armorer can set its own block threshold. The current eval baseline uses `0.80`,
so sensitive-data requests can be suspicious without always being blockable.

## Boundaries

Armorer Guard does not:

- call remote APIs
- execute tools
- mutate model weights
- store credentials
- train public models from unreviewed local feedback
- fetch third-party corpora at runtime
- rely on Python scanner logic

Armorer Guard does:

- classify text
- redact text
- capture credential values for the caller to store safely
- store sanitized local feedback when explicitly asked
- emit stable reasons and confidence

## Known Limitations

- The semantic lane is not a transformer classifier.
- The similarity lane uses simple token overlap, not embeddings.
- The current binary does not expose per-lane timing or per-lane confidence.
- The current binary is not a complete replacement for runtime confirmation
  policies in Armorer.

## Evaluation Expectations

The eval dashboard should track improvements across experiments:

- `baseline`
- `semantic-local-v1`
- `semantic-plus-similarity-v1`
- `semantic-plus-policy-v1`
- `context-aware-policy-v1`

Acceptance targets for the first smarter milestone:

- credential capture remains at `100%` on current credential cases
- benign false-positive rate stays under `5%`
- non-token expected-block recall reaches at least `70%`
- prompt injection, data exfiltration, safety bypass, and destructive command
  each reach at least `60%` recall
