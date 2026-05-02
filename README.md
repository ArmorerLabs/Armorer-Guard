# Armorer Guard

Private source for the Armorer Guard scanner binary.

Armorer is open source, but this scanner implementation is proprietary and should
stay in this private repository. Public Armorer releases should consume Guard as a
prebuilt binary or binary-only package instead of building it from source.

## Contract

Armorer Guard is a local-first Rust scanner. All detection, redaction,
classification, confidence scoring, and reason labeling live in `src/main.rs`.

The Python package is only a compatibility wrapper for Armorer and other Python
callers. It shells out to the packaged Rust binary and contains no detector
logic.

Public contract:

- `inspect_input(text, context=None)`
- `inspect_output(text, context=None)`
- `sanitize_text(text)`
- `detect_credentials(text, context=None)`
- `capabilities()`

CLI modes:

```bash
armorer-guard < input.txt
armorer-guard inspect < input.txt
armorer-guard sanitize < input.txt
armorer-guard detect-credentials < input.txt
armorer-guard capabilities
```

See:

- [Architecture](docs/ARCHITECTURE.md)
- [Capabilities](docs/CAPABILITIES.md)
- [Distribution](docs/DISTRIBUTION.md)

## Development

```bash
cargo test
cargo build --release
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

The intended distribution model is:

- build signed binaries for supported platforms in CI
- publish binary artifacts from this private repo
- have public Armorer discover the binary from `ARMORER_GUARD_BIN`, `PATH`, or a
  packaged installer-managed location

Do not publish this repository source publicly.
