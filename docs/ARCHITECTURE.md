# Armorer Guard Architecture

Armorer Guard is a public source-available, local-first security scanner used by
agent runtimes. The implementation boundary is deliberately simple:

- Rust owns all detection behavior.
- Python owns packaging compatibility only.
- Public Armorer discovers and executes the Guard binary.
- No scanner calls a network service by default.

## Runtime Shape

```text
Armorer public repo
  -> armorer.security.guard_backend
  -> optional armorer_guard Python package
  -> packaged armorer-guard Rust binary
  -> JSON result
```

The Python package should never grow independent scanner logic. If a capability
matters, implement it in Rust and expose it through the binary.

## Rust Binary

Source of truth:

- `src/main.rs`

Supported modes:

- `inspect`
- `sanitize`
- `detect-credentials`
- `capabilities`

The binary reads request text from `stdin` for scanner modes and writes JSON to
`stdout`. The `capabilities` mode emits the Rust-owned machine-readable scanner
contract.

## Python Package

Source files:

- `armorer_guard/__init__.py`
- `armorer_guard/cli.py`
- `armorer_guard/bin/armorer-guard`

The Python package exists because public Armorer is Python and needs a stable
import contract. It shells out to the Rust binary for every operation.

Allowed Python responsibilities:

- find the packaged binary
- invoke the binary with a mode
- parse JSON into Python dataclasses
- expose a CLI wrapper for Python packaging users

Disallowed Python responsibilities:

- credential detection
- prompt-injection detection
- semantic scoring
- policy scoring
- similarity scoring
- redaction logic

## Detection Lanes

Armorer Guard uses four Rust-owned lanes.

`credential_lane`

Deterministic token recognition, redaction, capture, provider inference, and
suggested key naming.

`semantic_lane`

Local semantic/rule scoring for non-token threats. This is currently lexical and
rule based. Future local model work should still be implemented behind the Rust
binary boundary.

`similarity_lane`

Local token-set similarity against Armorer-owned development exemplars from
`src/dev_exemplars.tsv`. This lane intentionally reads only provenance-tagged
`can_train=true` data and must never index eval case rows.

`policy_lane`

Runtime/action-aware labels for dangerous actions such as credential disclosure,
destructive operations, and bypassing guard controls.

## Why Rust

Guard needs to be small, local, portable, and easy to ship as a single binary.
Rust gives us:

- single binary distribution
- predictable local execution
- no Python scanner dependency leakage
- straightforward cross-platform CI
- a clear scanner boundary

## Future Scanner Work

The next smarter implementations should remain Rust-owned:

- keep release eval rows out of Rust rules, prompts, similarity exemplars, and
  classifier training data
- train or tune only on explicit `can_train=true` development data
- use regression and holdout suites as gates for generalization, not as prompt
  corpora to memorize

- ONNX-backed local classifier through a Rust runtime
- local embeddings/similarity index
- structured policy engine
- scanner registry
- JSONL trace output
- per-lane timing and confidence breakdown

If a Python library is useful during prototyping, treat it as an experiment only.
The production capability should land in Rust before release.
