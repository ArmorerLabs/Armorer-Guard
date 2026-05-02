# Armorer Guard Distribution

Armorer Guard is private. Public Armorer should consume it as a binary artifact,
not as source.

## Goal

Users should be able to install public Armorer and receive Guard functionality
without seeing Guard source code.

## Package Shape

The package contains:

- a prebuilt `armorer-guard` binary
- a thin Python wrapper
- no Rust source in the wheel
- no detector implementation in Python

The wrapper exists only to support:

- `import armorer_guard`
- `armorer_guard.inspect_input(...)`
- `armorer_guard.detect_credentials(...)`
- `armorer_guard.capabilities()`
- `armorer-guard-python`

## Binary Discovery In Public Armorer

Public Armorer should discover Guard in this order:

1. `ARMORER_GUARD_BIN`
2. Armorer-managed install path such as `~/.armorer/bin/armorer-guard`
3. `PATH`
4. binary-only Python package import, when installed
5. public built-in fallback, only when Guard is unavailable

The public fallback should remain visibly weaker and should report itself as a
fallback. It should never pretend to be the private Guard.

## CI Requirements

Every release should build and test:

- Linux
- macOS
- Windows

Minimum release checks:

```bash
cargo test --locked
cargo build --release --locked
python -m build --wheel
python -m pip install dist/*.whl
python -c "import armorer_guard; print(armorer_guard.capabilities())"
```

## Publishing Rules

Do:

- publish binary-only wheels/artifacts
- sign or checksum release artifacts
- keep source private
- verify that public Armorer can import and run Guard after install
- verify `armorer-guard capabilities`

Do not:

- publish this repository
- publish `src/main.rs`
- copy detector logic into public Armorer
- copy detector logic into the Python wrapper
- bundle unlicensed third-party prompt corpora

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

This is the fastest way to confirm that a user has the private binary-backed
Guard and not only the public fallback.
