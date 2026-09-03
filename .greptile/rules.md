# Armorer Guard SDK review rules

This repository has no `AGENTS.md` and no `CLAUDE.md`. The governing documents are
[`README.md`](../README.md), [`CONTRIBUTING.md`](../CONTRIBUTING.md), and
[`SECURITY.md`](../SECURITY.md), and the rules below restate them as checks a reviewer
can apply mechanically.

`Armorer-Guard` is a **public** repository. It is the customer-side integration surface
for a Guard runtime that Armorer delivers separately. Everything here is read by
customers and by anyone on the internet.

## 1. Repository boundary: nothing private lands here

`CONTRIBUTING.md` and `README.md` both draw this line. Block a pull request that adds:

- Guard runtime code or binaries, Rust runtime source, or a vendored runtime blob.
- Policy files, ML or evaluation assets, or reviewer implementations.
- Production logs, customer prompts, customer records, or reviewer traces.
- Credentials, tokens, signing keys, or production signing material.

Mechanical checks:

- Any new binary, archive, model file, or file over a few hundred KB needs a stated reason.
- Any new `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, or `*.ppk` is a block.
  `.gitignore` already excludes `*.pem` and `*.key`; a PR that removes those lines, or that
  adds a negation such as `!something.pem`, is a block.
- `tests/test_python_package.py::test_client_package_contains_no_embedded_runtime_api`
  asserts the package exposes no `binary_path` and no `inspect_input`. A PR that deletes or
  weakens that test is reintroducing the runtime-bundled surface v1.0 deliberately removed.
- Fixtures must stay synthetic. A "realistic" ticket body, tenant id, or trace id copied from
  a customer environment is customer data.

## 2. Guard decisions fail closed

The five admitted content effects are exactly `allow`, `allow_trusted_instruction`,
`allow_untrusted_data`, `warn_and_allow`, `redact_and_allow`, defined once as
`_ADMITTED_CONTENT_EFFECTS` in `armorer_guard/adapters.py` and once as
`ADMITTED_CONTENT_EFFECTS` in `npm/armorer-guard/index.js`. The remaining three
`ContentEffect` values (`quarantine`, `require_approval`, `deny`) must never be admitted.

Block any change that turns a missing or unrecognized value into a permissive path:

- A `decision.get("effect")` or `decision?.effect` fallback that supplies a default effect.
- `||`, `??`, or optional chaining that makes a missing `execution_token`, a missing
  `authorized`, or a missing `receipt_id` read as satisfied.
- Truthiness in place of the explicit identity checks: it is `dispatch.get("authorized") is
  not True` in Python and `dispatch?.authorized !== true` in Node, not `if (authorized)`.
- A `receipt_id` check loosened from "non-empty `str`" to merely present.
- A new `except` / `catch` that swallows a transport, parse, size-limit, or timeout error and
  returns a value. Every failure path in `GuardSidecar.request` and `GuardSidecarClient.request`
  raises; adding a lenient one defeats the whole client.
- A new adapter that re-implements effect handling instead of calling
  `_require_exact_content_admission` / `requireExactContentAdmission` or
  `requireContentAdmission`.

Effect membership must be tested against the set, never against a string prefix or a regex.

## 3. Token and receipt ordering is the enforcement contract

`protect_capability` (Python) and `protectCapability` (Node) implement one ordering, and
`examples/langgraph-typescript/src/guard-supervisor.ts` repeats it. It must stay:

1. `action(authority_request)` returns a decision.
2. `require_approval` raises `GuardApprovalRequired` / `GuardApprovalRequiredError`.
3. Effect is `allow` **and** `execution_token` is present, or it is a denial.
4. `authorize_execution({schema_version, token, observed_at})` returns `authorized === true`.
5. Only then the downstream call runs, receiving the token **verbatim**.
6. `record_execution(...)` returns a non-empty string `receipt_id`.
7. The result is returned wrapped with its receipt (`GuardedExecution` / `{result, executionReceipt}`).

Block:

- Any downstream call before step 4.
- Minting, mutating, re-signing, caching, reusing, or reconstructing the token. It is one-use
  and opaque to the SDK.
- Returning a result before the receipt is verified, or reporting success when the receipt is
  absent, empty, or not a string.
- Removing the failure path that records `downstream_outcome: "failed"` and raises
  `RECEIPT_RECORDING_FAILED` when the receipt attempt itself fails. That path preserves both
  errors for incident handling and is load-bearing.
- In the example, calling LangGraph's unguarded tool handler. The registered capability is the
  only implementation allowed to reach the protected gateway.

Regression tests that pin this: `test_protected_effect_requires_explicit_dispatch_authorization`,
`test_protected_effect_requires_execution_receipt`, `test_protected_effect_returns_result_with_receipt`,
and their Node counterparts in `npm/armorer-guard/test/client.test.js`.

## 4. Request paths stay on the allowlist

Both clients hand-roll HTTP/1.1 onto a Unix socket, a Windows named pipe, or a TLS socket, so
the path is concatenated straight into the request line. The only thing preventing CRLF header
injection is the allowlist:

- Python: `_API_PATH = re.compile(r"/v1/[A-Za-z0-9._~/-]+")` checked with `.fullmatch`.
- Node: `/^\/v1\/[A-Za-z0-9._~/-]+$/` in `requestPath`.

Block:

- Any new endpoint helper that builds a wire request without passing through that gate.
- Widening the character class, switching `fullmatch` to `match` or `search`, or dropping the
  `^`/`$` anchors.
- Interpolating caller-controlled data into the request line or into the `Host`,
  `Content-Type`, or `Content-Length` headers. Query strings and path parameters are not
  supported; identifiers belong in the JSON body.
- Accepting a method other than `GET` or `POST`.

`test_request_path_rejects_header_injection` and "request paths reject header injection" cover
this. Both must keep passing.

## 5. Python and Node are one contract in two languages

`CONTRIBUTING.md`: "When a contract must change, keep the Python and Node clients in sync and
include a compatibility test." A one-sided change is the defect this repository is most exposed
to, because nothing in CI compares the two clients automatically.

Any added, removed, or renamed item below must land in **all** the listed places in the same
pull request:

| Item | Files that must change together |
| --- | --- |
| A `/v1/...` route | `armorer_guard/client.py`, `npm/armorer-guard/index.js`, `npm/armorer-guard/index.d.ts` |
| A `schema_version` literal | `schemas/armorer-guard-runtime.schema.json`, `armorer_guard/contracts.py`, `armorer_guard/client.py`, `npm/armorer-guard/index.js`, `npm/armorer-guard/index.d.ts` |
| An admitted effect or `ContentEffect` value | `armorer_guard/contracts.py`, `armorer_guard/adapters.py`, `npm/armorer-guard/index.js`, `npm/armorer-guard/index.d.ts`, the JSON schema |
| An error code (`REQUEST_TOO_LARGE`, `RECEIPT_MISSING`, ...) | both clients |
| A default (`timeout` 2s, `max_body_bytes` 1 MiB, the `+ 64 KiB` response slack) | both clients |
| A new export | `armorer_guard/__init__.py` `__all__`, `npm/armorer-guard/index.js`, `npm/armorer-guard/index.d.ts` |

Add the matching test to **both** `tests/test_python_package.py` and
`npm/armorer-guard/test/client.test.js`. `test_sidecar_routes_use_only_public_runtime_endpoints`
asserts an exact ordered list of routes; a new route must be added there and in the Node
equivalent, or the assertion is silently incomplete.

Note the deliberate asymmetry, and do not "fix" it by accident: `canonical_json` in Python
delegates to `json.dumps(sort_keys=True)`, while Node implements canonicalisation by hand.
Both must produce byte-identical output, because `canonical_digest` and `sign_canonical` feed
HMACs the runtime verifies. `test_canonical_values_are_stable` and "canonical values are
stable" pin the same fixture in both languages; any change to either implementation must keep
that fixture's output character-for-character identical.

## 6. Schema changes are versioned, never edited in place

`schemas/armorer-guard-runtime.schema.json` is published at the stable `$id`
`https://armorer.dev/schemas/armorer-guard-runtime.schema.json` with 13 `$defs`.

- Adding a required property, tightening a type, narrowing an enum, or removing a `$defs`
  entry is breaking. It must bump the affected `schema_version` const (for example
  `armorer-guard-authority-request/v2`), not redefine an existing version.
- Flag any `$defs` edit that leaves its `schema_version` const untouched.
- Keep the `$id` and the `$schema` draft (`2020-12`) stable. CI runs
  `check-jsonschema --check-metaschema`, which validates the schema is well formed; it does
  **not** detect a breaking change to an already-published version.
- Contract literals currently in use: `armorer-guard-content-evaluation/v1`,
  `armorer-guard-content-decision/v1`, `armorer-guard-authority-request/v2`,
  `armorer-guard-authority-decision/v2`, `armorer-guard-execution-token/v1`,
  `armorer-guard-execution-dispatch/v1`, `armorer-guard-execution-report/v1`,
  `armorer-guard-execution-receipt/v1`.

## 7. Retrieved content is evidence, never instructions

`examples/langgraph-typescript/README.md` states it directly: ticket bodies and imported vendor
notes are evidence, never instructions. The `trust` and `instruction_authority` fields encode
that, and they are the fields most likely to be set wrongly.

Every `ContentSegment` must carry `content_ref`, `origin`, `principal_id`, `tenant_id`,
`trust`, `data_classes`, `instruction_authority`, and `retention`.

- Ticket bodies, tool results, imported vendor notes, and model output are
  `trust: "untrusted"` with `instruction_authority: "none"`.
- Only genuine application-owner context may be `trust: "platform"` or
  `instruction_authority: "system"` / `"developer"`.
- Block any promotion of retrieved or model-derived text to a higher trust class or authority,
  and any `tenant_id`, `principal_id`, or `purpose` read out of untrusted content.
- `content_ref` is a content digest. It must be derived from the text, not from a counter, a
  UUID, or a caller-supplied label, or the exact-admission check in rule 8 is meaningless.
- Do not weaken the per-session `content_ref` tracking in `guard-supervisor.ts`; it is what
  ties an admitted segment to the turn that may use it.

## 8. Generic adapters refuse to reconstruct transformed content

`_require_exact_content_admission` / `requireExactContentAdmission` admit a decision only when
the decided segments are an exact one-to-one, duplicate-free match of the source segments **and**
every `sanitized_text` equals the original `text`. Anything else raises
`CONTENT_TRANSFORM_UNSUPPORTED`, including a `redact_and_allow` that actually redacted.

This is intentional: a generic adapter cannot safely splice redacted text back into a
framework-specific payload. Block any change that:

- Substitutes `sanitized_text` into the outgoing payload in the generic adapters.
- Drops the duplicate-`content_ref` rejection or the three length equalities
  (`originals.size === envelope.segments.length === decision.segments.length`).
- Downgrades the raise to a warning or a log line.

A framework-specific adapter that genuinely can reconstruct redacted content must justify it
explicitly and carry its own tests in both languages.
`test_generic_model_adapter_fails_closed_on_transformed_content` and "generic model supervision
fails closed on transformed content" pin the current behaviour.

## 9. Transport identity is complete or absent

- A remote endpoint requires a **complete** mutually authenticated TLS identity. Python raises
  unless `ca_file`, `certificate_file`, and `private_key_file` are all present; Node requires
  `host`, a positive integer `port`, `ca`, `cert`, and `key`.
- `check_hostname = True`, `verify_mode = ssl.CERT_REQUIRED`, and `rejectUnauthorized: true`
  must stay. Any PR that sets them false, adds an `insecure` or `skipVerify` option, or accepts
  a CA from an environment variable without a stated reason is a block.
- Without mTLS, a socket path is mandatory (`socket_path` or `ARMORER_GUARD_SOCKET`). Do not add
  a plaintext TCP fallback.
- Keep both size limits: the request cap (`max_body_bytes`, default 1 MiB) and the response cap
  checked incrementally while reading. Removing the incremental response check reintroduces an
  unbounded read from the runtime socket.

`test_remote_guard_requires_complete_mtls_identity` and "remote Guard requires a complete mTLS
identity" cover the identity rule.

## 10. Workflow and metadata changes

- `.github/workflows/ci.yml` is the only workflow. Its matrix job produces the three check
  names branch protection requires: `Public clients (ubuntu-latest)`,
  `Public clients (macos-latest)`, `Public clients (windows-latest)`. **Renaming the job, its
  `name` expression, or a matrix `os` value breaks the required-check contract and blocks every
  merge.** Steps may be renamed freely; job names may not.
- Keep every action pinned to a full 40-character commit SHA with a trailing version comment.
  A tag or branch ref is a block.
- Keep top-level `permissions: contents: read`. A write scope, `pull_request_target`, a
  `secrets` reference, a publish/release step, or a `git push` to the default branch needs an
  explicit justification in this public repository.
- CI must keep mirroring the four commands `CONTRIBUTING.md` tells contributors to run. If one
  changes, change both.
- The Python and Node package versions (`pyproject.toml` `version`, both `package.json`
  `version`) move together, and the `>=3.10` / `>=22.19.0` floors in `pyproject.toml`,
  `package.json`, and the README badges must agree.

## 11. Disclosure hygiene in the pull request itself

Per `SECURITY.md`, an authentication or transport bypass, token replay, cross-tenant behaviour,
or sensitive-data handling issue is reported privately to `dev@armorerlabs.com` first. If a pull
request title, description, commit message, test name, or code comment in this **public**
repository describes such a weakness before a coordinated fix, say so and ask for it to move to
the private channel. Do not restate the details in the review comment.