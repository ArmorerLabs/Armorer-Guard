"""CrewAI-style guarded tool wrapper.

Wrap dangerous or outbound tools with `guard_tool_call` before the tool runs.
The same pattern works for file, browser, email, Slack, shell, database, and
HTTP tools.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import armorer_guard


def guard_tool_call(tool_name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        payload = {"args": args, "kwargs": kwargs}
        verdict = armorer_guard.inspect_input(
            repr(payload),
            context={
                "eval_surface": "tool_call_args",
                "trace_stage": "action",
                "tool_name": tool_name,
            },
        )
        if verdict.suspicious:
            raise RuntimeError(
                f"Armorer Guard blocked {tool_name}: "
                f"{verdict.reasons} confidence={verdict.confidence:.3f}"
            )
        return fn(*args, **kwargs)

    return wrapped


def send_email(to: str, body: str) -> str:
    return f"would send email to {to}: {body[:60]}"


safe_send_email = guard_tool_call("send_email", send_email)


if __name__ == "__main__":
    print(safe_send_email("team@example.com", "Weekly update attached."))

