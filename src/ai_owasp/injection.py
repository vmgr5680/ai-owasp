"""Part 1, LLM01:2026 Prompt Injection.

Two kinds of control live here, and the article is about the difference:

* Controls that try to stop the model being fooled (an input filter,
  stripping invisible characters). They help, and they leak.
* Controls that make a fooled model harmless (a tool policy in code, a
  render allowlist, the Rule of Two). They hold no matter what the model
  decided, because the model never gets to decide them.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .model import ToolCall

# --- 1. An input filter: the control most teams build first --------------
BLOCKLIST = re.compile(
    r"ignore (all )?(previous|prior) instructions|disregard your rules",
    re.I,
)


def input_filter(text: str) -> bool:
    """True if the text looks like an injection (English phrases only)."""
    return bool(BLOCKLIST.search(text))


# --- 2. Strip invisible characters at every ingest boundary --------------
INVISIBLE = re.compile(
    "[\\U000E0000-\\U000E007F"   # Unicode tag characters
    "\\uFE00-\\uFE0F"            # variation selectors
    "\\u200B\\u200C\\u200D\\u2060]"  # zero-width characters
)


def strip_invisible(text: str) -> str:
    return INVISIBLE.sub("", text)


# --- 3. A tool policy the model cannot talk its way past -----------------
def email_policy(call: ToolCall, user_email: str) -> tuple[bool, str]:
    """send_email may only reach the signed-in user's own address.
    Anything else needs a human, and here no human approved it."""
    if call.name != "send_email":
        return True, "not an email"
    if call.args["to"].lower() == user_email.lower():
        return True, "to the user's own address"
    return False, f"held for approval: {call.args['to']}"


# --- 4. Never auto-fetch images from origins you don't control -----------
MD_IMAGE = re.compile(r"!\[[^\]]*\]\((?P<url>[^)\s]+)\)")


def render_safely(text: str, allowed_hosts: set[str]) -> tuple[str, int]:
    """Replace markdown images whose host is not allowlisted."""
    removed = 0

    def swap(m: re.Match) -> str:
        nonlocal removed
        if urlparse(m["url"]).hostname in allowed_hosts:
            return m[0]
        removed += 1
        return "[image removed: untrusted origin]"

    return MD_IMAGE.sub(swap, text), removed


# --- 5. The Rule of Two, checked before deployment -----------------------
def rule_of_two(untrusted_input: bool, sensitive_data: bool,
                external_action: bool) -> str:
    legs = [n for n, on in (("A untrusted input", untrusted_input),
                            ("B sensitive data", sensitive_data),
                            ("C external action", external_action)) if on]
    if len(legs) == 3:
        return "HIGH RISK [A,B,C]: per-action human approval required"
    if len(legs) == 2 and untrusted_input:
        # OWASP names [A,B] and [A,C] as needing a residual-risk review
        return f"assess residual risk [{', '.join(l[0] for l in legs)}]"
    return "ok"
