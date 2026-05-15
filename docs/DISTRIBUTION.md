# Armorer Guard Distribution

Armorer Guard is public source-available software under the PolyForm
Noncommercial License 1.0.0. Commercial use requires a separate paid commercial
license from Armorer Labs.

## Package Shape

The package contains:

- a Rust `armorer-guard` binary
- a thin Python wrapper
- a thin Node/TypeScript wrapper under `npm/armorer-guard`
- a bundled native semantic classifier TSV for local/no-network runtime builds
- no detector implementation in Python or JavaScript

The Python wrapper exists only to support:

- `import armorer_guard`
- `armorer_guard.inspect_input(...)`
- `armorer_guard.detect_credentials(...)`
- `armorer_guard.capabilities()`
- `armorer-guard-python`

The Node wrapper exists only to support:

- `import { inspect, sanitize, requireSafeToolArgs } from "@armorerlabs/guard"`
- `armorer-guard-node inspect`
- `armorer-guard-node mcp-proxy -- ...`
- JavaScript/TypeScript projects that call the Rust binary through `PATH` or `ARMORER_GUARD_BIN`

## Binary Discovery

Downstream consumers should discover Guard in this order:

1. `ARMORER_GUARD_BIN`
2. installer-managed path such as `~/.armorer/bin/armorer-guard`
3. `PATH`
4. binary-backed Python package import, when installed
5. fallback scanner, only when Guard is unavailable

Fallbacks should remain visibly weaker and should report themselves as
fallbacks. They should never pretend to be the Rust Guard binary.

## Model Artifacts

The runtime build keeps `src/semantic_classifier_native.tsv` in this repository
so `cargo build` does not need network access.

Full reproducibility artifacts live in the public Hugging Face model repository:

https://huggingface.co/armorer-labs/armorer-guard-semantic-classifier

Use:

```bash
scripts/fetch_model_artifacts.sh
```

to download the public ONNX, joblib, labels, metrics, and native TSV artifacts
into a local ignored `models/` tree.

## CI Requirements

Every release should build and test:

- Linux
- macOS
- Windows

Minimum release checks:

```bash
cargo test --locked
cargo clippy -- -D warnings
cargo build --release --locked
python -m build --wheel
python -m pip install dist/*.whl
python -c "import armorer_guard; print(armorer_guard.capabilities())"
ARMORER_GUARD_BIN="$PWD/target/release/armorer-guard" npm test --prefix npm/armorer-guard
cd npm/armorer-guard && npm publish --dry-run --access public
brew tap ArmorerLabs/tap
brew install ArmorerLabs/tap/armorer-guard
brew test ArmorerLabs/tap/armorer-guard
```

## Publishing Rules

Do:

- publish binaries/wheels with clear noncommercial licensing
- publish `@armorerlabs/guard` only after `npm publish --dry-run --access public` is clean
- update `ArmorerLabs/homebrew-tap` after every CLI release
- sign or checksum release artifacts
- verify that downstream callers can import and run Guard after install
- verify `armorer-guard capabilities`
- keep full model artifacts in Hugging Face, not in the code repository

Do not:

- copy detector logic into downstream wrappers
- copy detector logic into the Python wrapper
- bundle unlicensed third-party prompt corpora
- train from regression, hard, or holdout eval rows

## Capability Verification

Downstream consumers should verify Guard by checking:

```bash
armorer-guard capabilities
```

Expected fields:

- `implementation_language: rust`
- `runtime_model: local_first_no_network`
- `lanes`
- `boundaries.python_detection_logic`
- `known_limitations`
