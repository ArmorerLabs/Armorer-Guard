"""Minimal MCP tool-call gate.

Use this pattern in an MCP proxy or client adapter before forwarding a tool
call to the real server.
"""

from __future__ import annotations

import json
from typing import Any

import armorer_guard


def assert_mcp_tool_call_is_safe(tool_name: str, arguments: dict[str, Any]) -> None:
    verdict = armorer_guard.inspect_input(
        json.dumps(arguments, separators=(",", ":")),
        context={
            "eval_surface": "tool_call_args",
            "trace_stage": "action",
            "tool_name": tool_name,
            "policy_scope": "mcp",
        },
    )
    if verdict.suspicious:
        raise PermissionError(
            json.dumps(
                {
                    "error": "blocked_by_armorer_guard",
                    "tool_name": tool_name,
                    "reasons": verdict.reasons,
                    "confidence": verdict.confidence,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    assert_mcp_tool_call_is_safe("filesystem.write_file", {"path": "notes.txt", "content": "ok"})

