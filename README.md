# Armorer Guard

Private source for the Armorer Guard scanner binary.

Armorer is open source, but this scanner implementation is proprietary and should
stay in this private repository. Public Armorer releases should consume Guard as a
prebuilt binary or binary-only package instead of building it from source.

## Development

```bash
cargo test
cargo build --release
```

The binary reads text from stdin and writes a JSON inspection response to stdout:

```bash
echo "GH_TOKEN=exampleSecretValue123456789" | cargo run --quiet
```

## Distribution

The intended distribution model is:

- build signed binaries for supported platforms in CI
- publish binary artifacts from this private repo
- have public Armorer discover the binary from `ARMORER_GUARD_BIN`, `PATH`, or a
  packaged installer-managed location

Do not publish this repository source publicly.
