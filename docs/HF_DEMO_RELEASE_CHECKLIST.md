# Hugging Face Demo Release Checklist

The demo should convert curious users into local installs.

## Required Presets

- Prompt injection.
- Credential leak.
- MCP tool call.
- Benign false positive.
- Learning Loop.

## Result Panel

Every scan should show:

- verdict
- reasons
- confidence
- sanitized text
- where the check belongs in an agent runtime
- copyable install command

## Manual Smoke

Before launch:

1. Open the Space.
2. Run every preset.
3. Confirm the MCP tool-call preset flags `policy:dangerous_tool_call`.
4. Confirm the credential preset redacts the secret.
5. Confirm links to GitHub, Cargo, PyPI, and the model card work.
