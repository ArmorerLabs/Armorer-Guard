"""Rich terminal presentation for the guarded-agent demo."""

from __future__ import annotations

import json
from dataclasses import dataclass
from threading import RLock
from typing import Any

from agents import RunHooks
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

REASON_LABELS = {
    "policy:credential_disclosure": "Credential disclosure",
    "semantic:prompt_injection": "Prompt injection",
    "semantic:sensitive_data_request": "Sensitive-data request",
    "semantic:system_prompt_extraction": "System-prompt extraction",
}


@dataclass
class OperationView:
    tool: str
    request: str
    guard: str = "Evaluating…"
    result: str = "Waiting"
    receipt: str = "—"


class DemoConsole:
    """Render a live security timeline without exposing hidden reasoning."""

    def __init__(self, *, verbose: bool = False) -> None:
        self.console = Console()
        self.verbose = verbose
        self.model = ""
        self.prompt = ""
        self.model_turn = 0
        self.status = "Starting Guard…"
        self.waiting_for_model = False
        self.operations: dict[str, OperationView] = {}
        self.live: Live | None = None
        self.lock = RLock()

    def banner(self, model: str, prompt: str) -> None:
        self.model = model
        self.prompt = prompt
        self._start_live()

    def guard_ready(self) -> None:
        self.status = "Guard ready · input and model route admitted"
        self._refresh()

    def event(self, kind: str, details: dict[str, Any]) -> None:
        with self.lock:
            operation_id = details.get("operation_id")
            operation = self.operations.get(operation_id)

            if kind == "tool_call":
                self.operations[operation_id] = OperationView(
                    tool=details["tool"],
                    request=self._request(details["resource_id"], details["arguments"]),
                )
            elif kind == "guard_decision" and operation is not None:
                operation.guard = details["effect"]
            elif kind == "approval_required" and operation is not None:
                operation.guard = "require approval"
                operation.result = "Waiting for owner"
                self.status = "Guard paused execution for human approval"
                self._refresh()
                self._stop_live()
                return
            elif kind == "approval_declined" and operation is not None:
                operation.result = "Not dispatched"
                self.status = "Approval declined"
                self._start_live()
            elif kind == "approval_consumed" and operation is not None:
                operation.result = "Approval verified"
                self.status = "Approval consumed · Guard re-evaluating action"
                self._start_live()
            elif kind == "receipt" and operation is not None:
                operation.receipt = self._short_receipt(details["receipt_id"])
                operation.result = details["outcome"]
            elif kind == "content_decision" and operation is not None:
                effect = details["effect"]
                operation.result = self._content_result(effect, details["reason_codes"])
            elif (
                kind == "tool_complete"
                and operation is not None
                and operation.result in {"Waiting", "succeeded", "Approval verified"}
            ):
                operation.result = details["status"].replace("_", " ")

            self._refresh()

    def llm_start(self) -> None:
        with self.lock:
            self.model_turn += 1
            self.waiting_for_model = True
            self.status = f"DeepSeek turn {self.model_turn} · choosing the next action"
            self._refresh()

    def llm_end(self) -> None:
        with self.lock:
            self.waiting_for_model = False
            self.status = f"DeepSeek turn {self.model_turn} · decision received"
            self._refresh()

    def confirm_approval(self, challenge: dict[str, Any], required_role: str) -> bool:
        presentation = challenge["presentation"]
        details = Table.grid(padding=(0, 2))
        details.add_column(style="bold yellow", no_wrap=True)
        details.add_column()
        details.add_row("Action", challenge["capability_id"])
        details.add_row("Resource", challenge["resource_id"])
        details.add_row("Role", required_role)
        details.add_row(
            "Arguments",
            json.dumps(presentation["normalized_arguments"], indent=2),
        )
        details.add_row("Risk", str(presentation["risk_score"]))
        details.add_row(
            "Scope",
            "Irreversible · exact arguments · one execution",
        )
        if presentation["warnings"]:
            details.add_row("Warnings", ", ".join(presentation["warnings"]))
        self.console.print(
            Panel(
                details,
                title="[bold yellow]Approval required[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED,
                padding=(1, 2),
            )
        )
        return Confirm.ask(
            "[bold yellow]Approve this one action?[/bold yellow]",
            default=False,
            console=self.console,
        )

    def final(self, response: str, events: list[dict[str, Any]]) -> None:
        self._stop_live()
        self.console.print(
            Panel(
                Markdown(response),
                title="[bold green]Agent result[/bold green]",
                border_style="green",
                box=box.ROUNDED,
                padding=(1, 2),
            )
        )
        self.console.print(self._audit_table(events))
        if self.verbose:
            self.console.print(
                Panel(
                    json.dumps(events, indent=2),
                    title="Raw Guard events",
                    border_style="dim",
                )
            )

    def cancelled(self) -> None:
        self._stop_live()
        self.console.print(
            Panel(
                "Guard stopped and temporary data removed.",
                title="[bold yellow]Demo cancelled[/bold yellow]",
                border_style="yellow",
            )
        )

    def _render(self) -> Group:
        header = Table.grid(padding=(0, 2))
        header.add_column(style="bold cyan", no_wrap=True)
        header.add_column()
        header.add_row("Model", self.model)
        header.add_row("Route", "OpenRouter · ZDR · no data collection")
        header.add_row("Policy", "tenant/demo · destructive actions require approval")
        header.add_row("Task", self.prompt)

        timeline = Table(
            box=box.SIMPLE_HEAVY,
            expand=True,
            show_edge=False,
            pad_edge=False,
        )
        timeline.add_column("Tool", style="bold cyan", no_wrap=True)
        timeline.add_column("Request", ratio=3)
        timeline.add_column("Guard", no_wrap=True)
        timeline.add_column("Result", ratio=2)
        timeline.add_column("Receipt", style="dim", no_wrap=True)
        if not self.operations:
            timeline.add_row("—", "Waiting for the agent", "—", "—", "—")
        for operation in self.operations.values():
            timeline.add_row(
                operation.tool,
                operation.request,
                self._guard_text(operation.guard),
                operation.result,
                operation.receipt,
            )

        if self.waiting_for_model:
            activity: Any = Spinner("dots", text=Text(self.status, style="magenta"))
        else:
            activity = Text(self.status, style="dim")
        return Group(
            Panel(
                header,
                title="[bold]Armorer Guard · Live Agent Demo[/bold]",
                border_style="cyan",
                box=box.ROUNDED,
            ),
            timeline,
            Panel(activity, border_style="dim", box=box.ROUNDED),
        )

    def _audit_table(self, events: list[dict[str, Any]]) -> Table:
        table = Table(
            title="Guard audit trail",
            box=box.ROUNDED,
            header_style="bold",
            expand=True,
        )
        table.add_column("#", justify="right", style="dim", width=3)
        table.add_column("Resource")
        table.add_column("Decision")
        table.add_column("Outcome")
        table.add_column("Receipt", style="dim")
        for index, event in enumerate(events, start=1):
            content_effect = event.get("content_effect")
            decision = content_effect or "authority allowed"
            table.add_row(
                str(index),
                event["resource_id"],
                self._guard_text(decision),
                event["status"].replace("_", " "),
                self._short_receipt(event.get("execution_receipt_id", "")),
            )
        return table

    def _start_live(self) -> None:
        if self.live is not None:
            return
        self.live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=8,
            transient=False,
        )
        self.live.start(refresh=True)

    def _stop_live(self) -> None:
        if self.live is None:
            return
        self.live.stop()
        self.live = None

    def _refresh(self) -> None:
        if self.live is not None:
            self.live.update(self._render(), refresh=True)

    def _content_result(self, effect: str, reason_codes: list[str]) -> str:
        if effect != "quarantine":
            return effect.replace("_", " ")
        reasons = (
            reason_codes
            if self.verbose
            else [REASON_LABELS.get(reason, "Policy signal") for reason in reason_codes]
        )
        return "Quarantined · " + ", ".join(reasons)

    @staticmethod
    def _request(resource_id: str, arguments: dict[str, Any]) -> str:
        visible_arguments = {
            key: value
            for key, value in arguments.items()
            if key not in {"operation", "record_id"}
        }
        if not visible_arguments:
            return resource_id
        return f"{resource_id} · {json.dumps(visible_arguments, sort_keys=True)}"

    @staticmethod
    def _short_receipt(receipt_id: str) -> str:
        if not receipt_id:
            return "—"
        return receipt_id.rsplit(":", 1)[-1][:10] + "…"

    @staticmethod
    def _guard_text(effect: str) -> Text:
        normalized = effect.replace("_", " ")
        styles = {
            "allow": "bold green",
            "authority allowed": "green",
            "allow untrusted data": "green",
            "require approval": "bold yellow",
            "quarantine": "bold red",
            "deny": "bold red",
        }
        return Text(normalized.upper(), style=styles.get(normalized, "yellow"))


class DemoRunHooks(RunHooks[Any]):
    """Show model-turn boundaries without exposing private chain-of-thought."""

    def __init__(self, console: DemoConsole) -> None:
        self.console = console

    async def on_llm_start(
        self,
        context: Any,
        agent: Any,
        system_prompt: str | None,
        input_items: list[Any],
    ) -> None:
        self.console.llm_start()

    async def on_llm_end(self, context: Any, agent: Any, response: Any) -> None:
        self.console.llm_end()
