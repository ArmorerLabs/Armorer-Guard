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

The `context` argument is accepted for compatibility and future policy work. The
current Rust binary does not consume it yet.

## Output Contract

`inspect_input` and `inspect_output` return:

- `sanitized_text`
- `suspicious`
- `reasons`
- `confidence`

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
- lexical/rule scoring
- no network calls
- no bundled model weights

This lane is the main target for future local classifier work.

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

## Eval Hygiene

Guard development data and release evaluation data are separate by design.

- `src/dev_exemplars.tsv` is the only current similarity source.
- Development exemplars must be Armorer-owned, provenance-tagged, and explicitly marked trainable.
- Regression, hard, and holdout eval case text must not be copied into Rust rules, similarity exemplars, classifier prompts, or model training data.
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

Armorer can set its own block threshold. The current eval baseline uses `0.80`,
so sensitive-data requests can be suspicious without always being blockable.

## Boundaries

Armorer Guard does not:

- call remote APIs
- execute tools
- mutate files
- store credentials
- train models
- fetch third-party corpora at runtime
- rely on Python scanner logic

Armorer Guard does:

- classify text
- redact text
- capture credential values for the caller to store safely
- emit stable reasons and confidence

## Known Limitations

- The semantic lane is not a transformer/ONNX classifier yet.
- The similarity lane uses simple token overlap, not embeddings.
- The current binary does not consume structured runtime context.
- The current binary does not expose per-lane timing or per-lane confidence.
- The current binary is not a complete replacement for runtime confirmation
  policies in Armorer.

## Evaluation Expectations

Current baseline should perform poorly on non-token semantic threats. That is
intentional. The eval dashboard should track improvements across experiments:

- `baseline`
- `semantic-local-v1`
- `semantic-plus-similarity-v1`
- `semantic-plus-policy-v1`

Acceptance targets for the first smarter milestone:

- credential capture remains at `100%` on current credential cases
- benign false-positive rate stays under `5%`
- non-token expected-block recall reaches at least `70%`
- prompt injection, data exfiltration, safety bypass, and destructive command
  each reach at least `60%` recall
