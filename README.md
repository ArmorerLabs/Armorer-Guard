# Armorer Guard

Armorer Guard is a local-first scanner for agent inputs, model outputs, and tool
calls. It detects and redacts credentials, flags prompt-injection and exfiltration
patterns, and reports structured JSON reasons that downstream agent runtimes can
enforce.

This repository is public source-available software. It is released under the
PolyForm Noncommercial License 1.0.0. Noncommercial research, evaluation,
personal, educational, and other permitted noncommercial uses are allowed under
that license. Commercial use requires a separate paid commercial license from
Armorer Labs.

Commercial licensing: dev@armorerlabs.com

## Contract

Armorer Guard is a Rust-owned scanner. Detection, redaction, classification,
confidence scoring, and reason labeling live in `src/main.rs`.

The Python package is a compatibility wrapper. It shells out to the packaged Rust
binary and contains no detector logic.

Public Python contract:

- `inspect_input(text, context=None)`
- `inspect_output(text, context=None)`
- `sanitize_text(text)`
- `detect_credentials(text, context=None)`
- `capabilities()`

CLI modes:

```bash
armorer-guard < input.txt
armorer-guard inspect < input.txt
armorer-guard inspect-json < request.json
armorer-guard sanitize < input.txt
armorer-guard detect-credentials < input.txt
armorer-guard semantic-scores < input.txt
armorer-guard capabilities
```

## Model Artifacts

The runtime Rust binary embeds `src/semantic_classifier_native.tsv` so local
builds work without network access.

Full model artifacts are published separately on Hugging Face:

https://huggingface.co/armorer-labs/armorer-guard-semantic-classifier

That model repository contains:

- `semantic_classifier_native.tsv`
- `semantic_classifier.onnx`
- `semantic_classifier.joblib`
- `labels.json`
- `metrics.json`

Use `scripts/fetch_model_artifacts.sh` to download the public model artifacts
when you need to inspect or reproduce the exported classifier files locally.

## Development

```bash
cargo test
cargo clippy -- -D warnings
cargo build --release
python3 -m pytest -q
```

The binary reads text from stdin and writes a JSON inspection response to stdout:

```bash
echo "GH_TOKEN=exampleSecretValue123456789" | cargo run --quiet
```

Inspect the Rust-owned capability contract:

```bash
cargo run --quiet -- capabilities
```

## Distribution

Armorer Guard is designed to run locally with no network calls in the scanner
path. Release builds should publish signed or checksummed binaries for supported
platforms and package the Python wrapper around those binaries.

Downstream callers can discover the binary from:

1. `ARMORER_GUARD_BIN`
2. an installer-managed path
3. `PATH`
4. a packaged Python wheel

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Capabilities](docs/CAPABILITIES.md)
- [ONNX classifier plan](docs/ONNX_CLASSIFIER_PLAN.md)
- [Distribution](docs/DISTRIBUTION.md)
