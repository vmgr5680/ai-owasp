"""Part 8, LLM08:2026 Hidden Context Exposure.

Assume everything you put in front of the model (system prompt, tool
schemas, retrieved policy text) can be read by the user. Then make sure
that reading it gets them nothing.
"""

from __future__ import annotations

import re

# --- an output filter that tries to keep the prompt secret ---------------
def leaks_prompt(output: str, system: str, window: int = 40) -> bool:
    """Block any output containing 40 consecutive characters of the
    system prompt. This is the filter people write first."""
    return any(system[i:i + window] in output
               for i in range(0, max(1, len(system) - window + 1)))


# --- an audit of what the hidden context contains ------------------------
RULES = [
    ("credential", "high",
     r"\b(sk-[A-Za-z0-9]{12,}|password\s*[:=]|api[_ ]key\s*[:=])"),
    ("authorization delegated to the model", "high",
     r"\b(admins?|role\s*=\s*\w+)\b.{0,40}\b(may|can|allowed)\b"),
    ("business limit or threshold", "medium",
     r"\$\s?\d[\d,]*|\blimit\b"),
    ("refusal trigger", "medium", r"if (asked|the user asks)"),
    ("privileged tool parameter", "medium",
     r"\b(override|bypass|admin)_\w+"),
]
ORDER = ["informational", "medium", "high", "critical"]


def audit(system: str, tools: list[dict]) -> tuple[str, list[tuple]]:
    """Return (overall severity, findings) for the hidden context."""
    text = system + "\n" + "\n".join(
        f"{t['name']}({', '.join(t['params'])}) {t.get('description', '')}"
        for t in tools)
    findings = []
    for name, severity, pattern in RULES:
        m = re.search(pattern, text, re.I)
        if m:
            findings.append((severity, name, m[0]))
    worst = max((ORDER.index(s) for s, _, _ in findings), default=0)
    return ORDER[worst], findings


# --- the version that trusts the model's tool arguments ------------------
def transfer_as_shipped(args: dict) -> str:
    """The limit and the admin rule only exist in the prompt, so the
    executor does whatever the model's tool call says."""
    if args["amount"] > 5000 and not args.get("override_limit"):
        return "refused by the model"
    return f"transferred ${args['amount']:,.0f}"


# --- the control that works: enforce it in code --------------------------
DAILY_LIMIT = 5000  # lives in code (or config), never in the prompt


def transfer(session_role: str, sent_today: float, amount: float) -> str:
    """The role comes from the authenticated session, not the chat."""
    if session_role != "admin" and sent_today + amount > DAILY_LIMIT:
        return f"refused: daily limit ({sent_today + amount:,.0f} > " \
               f"{DAILY_LIMIT:,})"
    return f"transferred ${amount:,.0f}"
