# Build a Real Guarded Agent

This example uses the OpenAI Agents SDK with OpenRouter and
`deepseek/deepseek-v4-flash-0731`. The model investigates records with four
tools, decides what evidence is relevant, and may propose a deletion; Armorer
Guard decides which exact operations may execute.

The protected effect is real but harmless. The runner creates `record/123` in a
temporary directory, and the tool can remove it only after Guard binds a human
approval to the model-proposed arguments and issues a single-use execution
token.

## How it works

```text
user prompt: investigate and remove the duplicate
  -> Guard input and model-route checks
  -> OpenAI Agents SDK / OpenRouter / DeepSeek V4 Flash 0731
  -> list_records / search_records / read_record
  -> Guard read authorization, execution tokens, and receipts
  -> Guard scans retrieved tool results before they re-enter model context
  -> model proposes delete_record(record_id, reason) from admitted evidence
  -> Guard destructive-action decision
  -> exact human approval challenge
  -> single-use execution token
  -> temporary record deletion
  -> execution receipt
  -> Guard output check
```

The LLM never receives the Guard client, signing keys, record store, or approval
service. Those are local SDK context dependencies. The model sees only the four
function-tool schemas.

## Agent tools

| Tool | Behavior | Guard boundary |
| --- | --- | --- |
| `list_records()` | Discover available record IDs | `record.read` authority, token, receipt, tool-result scan |
| `search_records(query)` | Search record text and return snippets | `record.read` authority, token, receipt, tool-result scan |
| `read_record(record_id)` | Retrieve one complete record | `record.read` authority, token, receipt, tool-result scan |
| `delete_record(record_id, reason)` | Delete one record | `record.delete`, exact human approval, single-use token, receipt |

The demo seeds a duplicate, its canonical record, and a poisoned record containing
a prompt-injection instruction. If the agent retrieves the poisoned record, Guard
returns `content_quarantined` without exposing its text to the next model turn.

## Project map

```text
guarded-agent/
├── README.md
├── requirements.txt
├── run.py                    # Live SDK runner and Guard input/output boundary
├── app/
│   ├── agent.py              # Agent, local context, and Guard-mediated tool
│   ├── approver.py           # Console approval and demo-only signer
│   ├── display.py            # Rich live dashboard, approval UI, and audit summary
│   ├── guard.py              # Sidecar contracts, tokens, and receipts
│   ├── offline.py            # Deterministic CI security-contract exercise
│   └── tools.py              # Real temporary record store
├── config/
│   ├── agent-manifest.template.json
│   └── guard-policy.json
├── fixtures/
│   ├── cross-tenant-action.json
│   ├── delete-action.json
│   ├── hostile-retrieval.json
│   └── safe-message.json
└── tests/
    └── test_security_contract.py
```

## Run the live agent

From the repository root:

```bash
cargo build --release
python3 -m venv .venv
.venv/bin/python -m pip install -r examples/guarded-agent/requirements.txt
```

For the Armorer demo, load the existing Trendy Llamas OpenRouter credential
directly from Bitwarden Secrets Manager without exporting the secret value:

```bash
export BWS_OPENROUTER_SECRET_ID="$(
  bws secret list --output json \
    | jq -r '.[] | select(.key == "OPENROUTER_TRENDY_LLAMAS_API_KEY") | .id'
)"
PYTHONPATH=.:examples/guarded-agent .venv/bin/python examples/guarded-agent/run.py
```

Alternatively, set `OPENROUTER_API_KEY` in the environment. The runner gives it
precedence over BWS. Never put the API key in this repository, the Guard policy,
or a prompt.

The default model is `deepseek/deepseek-v4-flash-0731`; override it with
`OPENROUTER_MODEL` or `--model`. The OpenAI Agents SDK uses its OpenAI-compatible
chat-completions model adapter against `https://openrouter.ai/api/v1`. Every
request sets OpenRouter's `provider.zdr=true`, `data_collection=deny`, and
`require_parameters=true`. The run makes a real provider request and may incur
API charges.

The default prompt asks the agent to discover the records, establish which one is
a duplicate, and delete only that record. The model chooses its own tool sequence.
Guard prints the exact deletion arguments and waits for `y` before allowing the
effect. For a non-interactive development run only:

```bash
PYTHONPATH=.:examples/guarded-agent .venv/bin/python \
  examples/guarded-agent/run.py --auto-approve
```

The Rich CLI dashboard correlates each agent tool call with its exact Guard
decision, sanitized outcome, and shortened execution-receipt ID. It pauses the
live view for a prominent human-approval panel, then finishes with the model's
answer and a durable audit table. Dashboard snapshots remain in terminal
scrollback when the display pauses or finishes, so earlier actions stay visible.
It intentionally does not expose private chain-of-thought; “choosing the next
action” is a high-level activity indicator. Pressing Ctrl-C exits cleanly and
removes the temporary Guard runtime and records.

For policy development, add `--verbose` to retain raw Guard reason codes and
print the complete event JSON after the readable audit table:

```bash
PYTHONPATH=.:examples/guarded-agent .venv/bin/python \
  examples/guarded-agent/run.py --verbose
```

SDK tracing is disabled by default to avoid exporting prompts and tool
arguments. Pass `--enable-sdk-tracing` only when that data flow is acceptable.

## Verify without an API call

The offline test runs the full Guard path—quarantine, fixed denial, approval,
token dispatch, real deletion, receipt, and replay rejection—without importing
the Agents SDK or contacting OpenAI:

```bash
PYTHONPATH=. python3 -m unittest discover -s examples/guarded-agent/tests
```

## Learn by changing it

- Ask a question that needs no action; the model should answer without calling
  the tool.
- Ask it to find the duplicate; the model can list, search, and read before it
  proposes deletion.
- Ask it to read `record/poisoned`; Guard quarantines the tool result before the
  hostile instructions can enter the next model turn.
- Decline the approval; the model receives `approval_declined` and cannot
  dispatch the deletion.
- Ask to delete another record; Guard may authorize the capability, but the
  isolated store reports that no record was removed.
- Change the fixture's tenant and observe the fixed cross-tenant invariant.
- Remove `record.delete` from delegated capabilities and observe a denial.
- Add a new tool by defining its capability in both the manifest and policy,
  then putting its real effect behind `guard.dispatch`.

## Production boundaries

- `DevelopmentApprover` and deterministic keys exist only to keep this demo
  self-contained. Production approval signing belongs outside the agent host.
- A protected service credential must not be available through an unguarded
  route. Guard is the execution gateway, not merely a logging callback.
- An `allow` decision is not proof of execution. The downstream receipt records
  whether dispatch occurred and its outcome.
- Guard is not an OS sandbox. Pair it with process isolation and least-privilege
  operating-system permissions.
- Guard policy contracts are strict JSON. YAML would imply an unsupported
  parser and is intentionally not used here.
