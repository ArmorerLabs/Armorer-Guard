# Armorer Guard v0.3.0 Release Notes

Armorer Guard v0.3.0 adds a structured tool-event policy lane for agent runtimes that need deterministic, auditable decisions at the moment of tool use.

## Highlights

- `inspect-json` now accepts an optional `tool_event` object alongside `text` and `context`.
- Guard responses include optional `rule_ids` and `affected_paths` for machine-readable receipts.
- The new tool-event policy lane detects sensitive path access, sandbox bypass attempts, dangerous shell patterns, remote shell pipes, MCP or skill poisoning, persistence vectors, self-protection tampering, and credential exfiltration patterns.
- Existing text-only `inspect` and `{ text, context }` JSON callers remain valid.
- Python and Node wrappers continue to shell out to the Rust binary; detector logic remains in the Guard package.

## Release Validation

Minimum local validation for this release:

```bash
cargo test --locked
cargo clippy -- -D warnings
bash scripts/smoke.sh
python3 -m pytest -q
ARMORER_GUARD_BIN="$PWD/target/release/armorer-guard" npm test --prefix npm/armorer-guard
npm publish --dry-run --access public --prefix npm/armorer-guard
cargo publish --dry-run --allow-dirty --locked
```

Armorer integration should also pass `pnpm build`, `pnpm test`, `pnpm typecheck`, `pnpm --filter armorer-ui-selfhost build`, `cargo test --workspace`, and `pnpm armorer -- guard health-check` with the v0.3.0 Guard binary.
