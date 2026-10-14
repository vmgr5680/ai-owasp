"""Part 2, LLM02:2026 Sensitive Information Disclosure.

The answer is only one way data leaks. Retrieved chunks, context fields,
logs and traces leak too. These helpers control what reaches the model and
what leaves the application, in that order.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# --- retrieval: authorize before ranking, not after ----------------------
@dataclass
class Chunk:
    id: str
    tenant: str
    text: str


def words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower())) - STOP


STOP = {"the", "a", "an", "of", "for", "to", "and", "is", "our", "on",
        "in", "what", "we", "with", "at", "by", "be", "it", "this"}


def search(chunks: list[Chunk], query: str, k: int = 2,
           tenant: str | None = None) -> list[Chunk]:
    """Rank by word overlap. If `tenant` is given, the filter runs inside
    the query, before ranking, so other tenants' chunks never compete."""
    pool = [c for c in chunks if tenant is None or c.tenant == tenant]
    q = words(query)
    scored = sorted(pool, key=lambda c: -len(q & words(c.text)))
    return [c for c in scored[:k] if q & words(c.text)]


# --- minimise context: send only the fields the task needs ---------------
TEMPLATES = {
    "parcel_status": ["order_id", "status", "eta"],
    "update_address": ["order_id", "status", "ship_to"],
}
SENSITIVE_FIELDS = {"date_of_birth", "ssn", "card_number", "phone",
                    "email", "ship_to", "support_notes", "credit_score"}


def minimise(record: dict, template: str) -> dict:
    return {k: record[k] for k in TEMPLATES[template]}


# --- a small scrubber: patterns plus a checksum --------------------------
PATTERNS = {
    "EMAIL": r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+",
    "PHONE": r"\(?\b\d{3}\)?[ -]\d{3}-\d{4}\b",
    "SSN": r"\b9\d{2}-\d{2}-\d{4}\b",
    "API_KEY": r"\bsk-[A-Za-z0-9]{16,}\b",
    "CARD": r"\b(?:\d[ -]?){13,16}\b",
}


def luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in digits if d.isdigit()][::-1]
    total = sum(n if i % 2 == 0 else (n * 2 - 9 if n > 4 else n * 2)
                for i, n in enumerate(nums))
    return total % 10 == 0


def scrub(text: str) -> tuple[str, list[str]]:
    found = []
    for label, pattern in PATTERNS.items():
        def sub(m, label=label):
            if label == "CARD" and not luhn_ok(m[0]):
                return m[0]
            found.append(label)
            return f"[{label}]"
        text = re.sub(pattern, sub, text)
    return text, found


def scrub_trace(trace: dict) -> tuple[dict, int]:
    """Treat every field of a trace as output: scrub them all."""
    clean, n = {}, 0
    for key, value in trace.items():
        if isinstance(value, list):
            out = []
            for v in value:
                s, f = scrub(v)
                out.append(s)
                n += len(f)
            clean[key] = out
        else:
            clean[key], f = scrub(value)
            n += len(f)
    return clean, n
