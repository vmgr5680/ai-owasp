"""Part 10, LLM10:2026 Improper Output Handling.

Model output is untrusted input to whatever receives it next. Each sink
(a database, a browser, a shell, a file system, a terminal) needs the
same treatment you would give a stranger's form submission.
"""

from __future__ import annotations

import html
import json
import re
import sqlite3
from pathlib import Path

# --- database: the model chooses an intent, code writes the SQL ----------
INTENTS = {"order_status": "SELECT id, status FROM orders WHERE id = ?"}


def run_intent(conn: sqlite3.Connection, model_json: str):
    """Model output must be JSON naming an allowed intent and its
    parameters. The SQL text is never the model's."""
    data = json.loads(model_json)
    sql = INTENTS.get(data.get("intent"))
    if sql is None:
        raise ValueError(f"intent not allowed: {data.get('intent')!r}")
    order_id = str(data.get("order_id", ""))
    if not re.fullmatch(r"ORD-\d{4}", order_id):
        raise ValueError(f"bad order_id: {order_id!r}")
    return conn.execute(sql, (order_id,)).fetchall()


# --- browser: encode for HTML ---------------------------------------------
def render_html(model_text: str) -> str:
    return f"<div class='answer'>{html.escape(model_text)}</div>"


# --- file system: resolve, then check it is still inside the base --------
def safe_path(base: Path, model_filename: str) -> Path:
    target = (base / model_filename).resolve()
    if not target.is_relative_to(base.resolve()):
        raise PermissionError(f"outside {base.name}/: {model_filename}")
    return target


# --- terminals and logs: neutralise control characters --------------------
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def neutralise(text: str) -> str:
    """Make ESC, BEL, carriage returns and friends visible instead of
    letting the terminal act on them."""
    return CONTROL.sub(lambda m: f"\\x{ord(m[0]):02x}", text)
