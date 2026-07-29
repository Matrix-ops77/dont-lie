"""dontlie TUI — an interactive receipt explorer.

Run with:
    python3 -m dontlie ui
    python3 -m dontlie ui --limit 200
    python3 -m dontlie ui --vault /path/to/vault.db

Keybindings:
    r         refresh from disk
    v         run verify on the whole chain
    /         focus the search box
    t         toggle live tail (poll every 2s)
    enter     show full prompt/response of the highlighted receipt
    j / k     next / previous receipt
    g / G     jump to top / bottom
    ?         show help
    q         quit
"""
from __future__ import annotations

import argparse
import sys
import threading
from datetime import datetime
from pathlib import Path

from rich.console import Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Static,
)

from . import storage
from .storage import Receipt, VerificationReport


def _shorten(value: str | None, n: int = 16) -> str:
    if not value:
        return "-"
    return value if len(value) <= n else value[:n] + "…"


def _fmt_ts(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts


def _fetch_receipts(limit: int, offset: int = 0) -> list[Receipt]:
    return storage.list_receipts(limit=limit, offset=offset)


def _verify_chain() -> VerificationReport:
    return storage.verify_chain_report()


def _get_receipt(receipt_id: int) -> Receipt | None:
    return storage.get_receipt(receipt_id)


class ReceiptTable(DataTable):
    """Two-column receipt list: id+model+timestamp on the left."""

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
    ]

    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.add_columns("#", "timestamp", "model", "parent", "key", "prompt")
        self.refresh_data()

    def refresh_data(self, limit: int = 200) -> None:
        self.clear()
        try:
            receipts = _fetch_receipts(limit=limit)
        except Exception as exc:  # pragma: no cover - defensive
            self.add_row("-", "-", "ERROR", "-", "-", str(exc))
            return
        for r in receipts:
            ts = _fmt_ts(r.timestamp)
            parent = str(r.parent_id) if r.parent_id is not None else "—"
            key = _shorten(r.key_id, 8)
            prompt_preview = (r.prompt or "").replace("\n", " ")[:60]
            if len(r.prompt or "") > 60:
                prompt_preview += "…"
            self.add_row(
                str(r.id),
                ts,
                r.model or "?",
                parent,
                key,
                prompt_preview,
                key=str(r.id),
            )


class DetailPane(Static):
    """Right-hand panel showing one full receipt."""

    receipt_id: reactive[int | None] = reactive(None)

    def render_receipt(self, receipt_id: int | None) -> None:
        self.receipt_id = receipt_id
        if receipt_id is None:
            self.update(Panel("Select a receipt to view details", title="Receipt"))
            return
        r = _get_receipt(receipt_id)
        if r is None:
            self.update(Panel(f"Receipt {receipt_id} not found", title="Receipt"))
            return
        body = Table.grid(padding=(0, 1))
        body.add_column(style="bold cyan", justify="right")
        body.add_column()
        body.add_row("id", str(r.id))
        body.add_row("timestamp", r.timestamp)
        body.add_row("model", r.model or "?")
        body.add_row("parent", str(r.parent_id) if r.parent_id is not None else "—")
        body.add_row("key_id", r.key_id)
        body.add_row("tags", ", ".join(r.tags) if r.tags else "—")
        body.add_row("payload_sha256", r.payload_sha256 or "—")
        body.add_row("signature", r.signature or "—")
        if r.extra:
            body.add_row("extra", repr(r.extra)[:200])

        prompt_panel = Panel(
            Syntax(r.prompt or "(empty)", "json", theme="monokai", word_wrap=True)
            if (r.prompt or "").strip().startswith(("{", "["))
            else Text(r.prompt or "(empty)"),
            title="prompt",
            border_style="blue",
        )
        response_panel = Panel(
            Syntax(r.response or "(empty)", "json", theme="monokai", word_wrap=True)
            if (r.response or "").strip().startswith(("{", "["))
            else Text(r.response or "(empty)"),
            title="response",
            border_style="green",
        )

        meta_panel = Panel(body, title=f"Receipt #{r.id}", border_style="cyan")
        self.update(
            Group(meta_panel, prompt_panel, response_panel)
        )


class StatusBar(Static):
    """Bottom status line with counts and verify result."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._message = "Press ? for help, q to quit"

    def show_message(self, message: str) -> None:
        self._message = message
        self.refresh()

    def show_verify(self, report: VerificationReport) -> None:
        total = report.ok_count + report.bad_count
        if report.ok_count and not report.bad_count:
            text = (
                f"[bold green]✓ verified[/]  "
                f"{report.ok_count} ok / {report.bad_count} bad / {total} total"
            )
        elif report.bad_count:
            text = (
                f"[bold red]✗ TAMPERED[/]  "
                f"{report.ok_count} ok / {report.bad_count} bad / {total} total"
            )
        else:
            text = "[yellow]? empty vault[/]"
        self._message = text
        self.refresh()

    def render(self) -> Text:  # type: ignore[override]
        return Text.from_markup(self._message)


class HelpScreen(Static):
    def compose(self) -> ComposeResult:
        yield Static(
            Panel(
                "[bold]dontlie ui — interactive receipt explorer[/]\n\n  r         refresh from disk\n  v         run verify on the whole chain\n  /         focus the search box\n  t         toggle live tail (poll every 2s)\n  enter     show full receipt\n  j / k     next / previous receipt\n  g / G     jump to top / bottom\n  ?         toggle this help\n  q         quit\n\n[dim]Press any key to close.[/]",
                title="Help",
                border_style="yellow",
            )
        )


class DontlieApp(App):
    CSS = """
    Screen { layout: vertical; }
    #main { height: 1fr; }
    #left { width: 60%; border: solid green; }
    #right { width: 40%; border: solid cyan; }
    #status { height: 1; background: $boost; color: $text; padding: 0 1; }
    #search { height: 3; }
    #help { align: center middle; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("v", "verify", "Verify"),
        Binding("t", "toggle_tail", "Tail"),
        Binding("slash", "focus_search", "Search"),
        Binding("question_mark", "toggle_help", "Help"),
    ]

    tailing: reactive[bool] = reactive(False)

    def __init__(self, limit: int = 200) -> None:
        super().__init__()
        self.limit = limit
        self._tail_thread: threading.Thread | None = None
        self._tail_stop = threading.Event()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="main"):
            yield Input(placeholder="Search prompt/response/tags (press / to focus)", id="search")
            with Horizontal():
                yield ReceiptTable(id="left")
                yield DetailPane(id="right")
        yield StatusBar(id="status")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Don't-Lie"
        self.sub_title = f"vault: {storage.DB_PATH}"
        storage.init()
        self._refresh_table()
        self._refresh_status(message="ready · press r to refresh, v to verify, / to search, ? for help")

    # ---- actions ----
    def action_refresh(self) -> None:
        self._refresh_table()
        self._refresh_status(message="refreshed")

    def action_verify(self) -> None:
        try:
            report = _verify_chain()
            self.query_one(StatusBar).show_verify(report)
        except Exception as exc:  # pragma: no cover - defensive
            self._refresh_status(message=f"verify error: {exc}")

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_toggle_help(self) -> None:
        self.push_screen("help")  # placeholder if we add a screen

    def action_toggle_tail(self) -> None:
        self.tailing = not self.tailing
        if self.tailing:
            self._refresh_status(message="tailing ON (refreshes every 2s) — press t to stop")
            self._start_tail()
        else:
            self._stop_tail()
            self._refresh_status(message="tailing OFF")

    def _start_tail(self) -> None:
        if self._tail_thread and self._tail_thread.is_alive():
            return
        self._tail_stop.clear()

        def loop() -> None:
            while not self._tail_stop.is_set():
                self.call_from_thread(self._refresh_table)
                self._tail_stop.wait(2.0)

        self._tail_thread = threading.Thread(target=loop, daemon=True)
        self._tail_thread.start()

    def _stop_tail(self) -> None:
        self._tail_stop.set()

    # ---- events ----
    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        try:
            rid = int(event.row_key.value) if event.row_key else None
        except (TypeError, ValueError):
            rid = None
        self.query_one(DetailPane).render_receipt(rid)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        try:
            rid = int(event.row_key.value) if event.row_key else None
        except (TypeError, ValueError):
            return
        r = _get_receipt(rid)
        if r is None:
            return
        # Pop a modal-style full-screen view
        full = Panel(
            f"[bold]#{r.id}[/]  {r.timestamp}  [cyan]{r.model}[/]\n"
            f"parent: {r.parent_id}   key: {r.key_id}\n"
            f"sha256: {r.payload_sha256}\n"
            f"sig:    {r.signature}\n\n"
            f"[bold blue]PROMPT[/]\n{r.prompt or '(empty)'}\n\n"
            f"[bold green]RESPONSE[/]\n{r.response or '(empty)'}\n\n"
            f"[dim]Press q to close[/]",
            title=f"Receipt {r.id}",
            border_style="cyan",
        )
        self.notify(str(full), title=f"Receipt {r.id}", timeout=8)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        q = event.value.strip()
        if not q:
            self._refresh_table()
            return
        try:
            hits = storage.search(q, limit=self.limit)
        except Exception as exc:  # pragma: no cover - defensive
            self._refresh_status(message=f"search error: {exc}")
            return
        table = self.query_one(ReceiptTable)
        table.clear()
        for r in hits:
            ts = _fmt_ts(r.timestamp)
            parent = str(r.parent_id) if r.parent_id is not None else "—"
            key = _shorten(r.key_id, 8)
            prompt_preview = (r.prompt or "").replace("\n", " ")[:60]
            if len(r.prompt or "") > 60:
                prompt_preview += "…"
            table.add_row(
                str(r.id),
                ts,
                r.model or "?",
                parent,
                key,
                prompt_preview,
                key=str(r.id),
            )
        self._refresh_status(message=f"search: {len(hits)} hits for {q!r} (press r to clear)")

    # ---- helpers ----
    def _refresh_table(self) -> None:
        self.query_one(ReceiptTable).refresh_data(limit=self.limit)

    def _refresh_status(self, message: str) -> None:
        self.query_one(StatusBar).show_message(message)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dontlie ui", description=__doc__)
    parser.add_argument("--limit", type=int, default=200, help="max receipts to load (default: 200)")
    parser.add_argument(
        "--vault",
        type=Path,
        default=None,
        help="path to vault.db (default: $DONTLIE_DB or ~/.local/share/dontlie/vault.db)",
    )
    args = parser.parse_args(argv)

    if args.vault is not None:
        storage.DB_PATH = args.vault
    elif "DONTLIE_DB" in os.environ if False else False:  # noqa: keep simple
        storage.DB_PATH = Path(os.environ["DONTLIE_DB"])
    storage.init()

    app = DontlieApp(limit=args.limit)
    app.run()
    return 0


if __name__ == "__main__":
    import os
    sys.exit(main())
