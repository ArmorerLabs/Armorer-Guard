# Contributing

Armorer Guard accepts focused contributions to the public client SDKs, wire
contracts, framework integrations, tests, and documentation in this repository.

By contributing, you agree that your contribution can be distributed by
Armorer Labs under this repository's MIT license.

Do not add private runtime code or binaries, policies, ML or evaluation assets,
reviewer implementations, production logs, credentials, tokens, or customer
data. When a contract must change, keep the Python and Node clients in sync and
include a compatibility test.

Before opening a pull request, run:

```bash
python -m pytest -q
npm test --prefix npm/armorer-guard
npm ci --prefix examples/langgraph-typescript
npm test --prefix examples/langgraph-typescript
```
