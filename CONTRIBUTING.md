# Contributing

Armorer Guard accepts focused contributions that improve local scanner quality,
packaging, documentation, tests, and reproducibility.

By contributing, you agree that your contribution can be distributed by Armorer
Labs under this repository's license and under separate commercial licenses.

Please keep changes small and include tests for scanner behavior changes.

Before opening a pull request, run:

```bash
cargo test
cargo clippy -- -D warnings
python3 -m pytest -q
```

Do not add third-party prompt corpora, copied eval rows, private logs, or
credentials. Training rows and exemplars must be Armorer-owned or explicitly
licensed for this use.
