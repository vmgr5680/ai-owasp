"""Part 3, LLM03:2026 Excessive Agency.

Three separate dials, each enforced in code the model cannot reach:
functionality (which tools exist), permissions (what the identity behind a
tool may do) and autonomy (which actions need a human). Plus two damage
limiters: graduated enforcement and a cumulative-value circuit breaker.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from .model import ToolCall


# --- dial 1 and 2: the tools offered, and the scope behind them ----------
class Forbidden(Exception):
    pass


@dataclass
class MailBackend:
    """Stands in for the mail provider. It checks the token's scopes on
    every request (complete mediation), whatever the agent believes."""
    sent: list[dict] = field(default_factory=list)

    def send(self, token_scopes: set[str], to: str, body: str) -> str:
        if "mail.send" not in token_scopes:
            raise Forbidden("403, token lacks mail.send")
        self.sent.append({"to": to, "body": body})
        return f"sent to {to}"


@dataclass
class Agent:
    tools: set[str]              # dial 1: functionality
    scopes: set[str]             # dial 2: permissions
    approval: set[str]           # dial 3: autonomy, tools needing a human
    backend: MailBackend
    queue: list[ToolCall] = field(default_factory=list)

    def execute(self, call: ToolCall) -> str:
        if call.name not in self.tools:
            return f"refused: {call.name} is not offered"
        if call.name in self.approval:
            self.queue.append(call)
            return "queued for the user to approve"
        if call.name != "send_email":
            return f"{call.name}: ok (no mail sent)"
        try:
            return self.backend.send(self.scopes, call.args["to"],
                                     call.args["body"])
        except Forbidden as e:
            return f"mail server: {e}"


# --- dial 2 for databases: the connection's identity, enforced by SQLite --
def read_only_products(conn: sqlite3.Connection) -> None:
    """Allow SELECT on the products table and nothing else."""
    def authorizer(action, arg1, arg2, dbname, source):
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ:
            return sqlite3.SQLITE_OK if arg1 == "products" \
                else sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_DENY
    conn.set_authorizer(authorizer)


# --- damage limiters: graduated enforcement + a circuit breaker ----------
@dataclass
class RefundGate:
    """Store credit is recoverable, so small amounts auto-approve.
    Cash payouts are not, so they always go to a human. A breaker trips
    when auto-approved credit in one window passes a ceiling."""
    auto_limit: float = 200.0
    window_ceiling: float = 500.0
    window_seconds: int = 3600
    approved_in_window: float = 0.0
    tripped: bool = False
    window_start: float = 0.0

    def decide(self, kind: str, amount: float, now: float = 0.0) -> str:
        if now - self.window_start >= self.window_seconds:
            # a new hour: reset the running total and close the breaker
            self.window_start, self.approved_in_window = now, 0.0
            self.tripped = False
        if kind == "payout":
            return "human review (irreversible)"
        if self.tripped:
            return "blocked: breaker open"
        if amount > self.auto_limit:
            return "human review (over auto limit)"
        if self.approved_in_window + amount > self.window_ceiling:
            self.tripped = True
            return "blocked: breaker tripped"
        self.approved_in_window += amount
        return "auto-approved"
