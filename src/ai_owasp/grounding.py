"""Part 7, LLM07:2026 Misinformation.

Claim, check, act: the model may claim anything, but nothing acts on a
claim until code has checked it against a source of truth.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Claim:
    text: str          # what the model wants to tell the user
    source_id: str     # the document it says supports it
    quote: str         # the exact words it says it relied on


def check_claim(claim: Claim, sources: dict[str, str]) -> list[str]:
    """Return the problems; an empty list means the claim is supported."""
    problems = []
    doc = sources.get(claim.source_id)
    if doc is None:
        return [f"cited source '{claim.source_id}' does not exist"]
    if claim.quote not in doc:
        problems.append("quoted words are not in the cited source")
    quoted_numbers = set(re.findall(r"\d+", claim.quote))
    for number in re.findall(r"\d+", claim.text):
        if number not in quoted_numbers:
            problems.append(f"'{number}' in the claim is not in the quote")
    return problems


def check_state(claim: dict, system_of_record: dict) -> list[str]:
    """Compare what an agent says happened with what the system says."""
    problems = []
    for key, value in claim.items():
        actual = system_of_record.get(key)
        if actual != value:
            problems.append(f"{key}: agent says {value!r}, "
                            f"system says {actual!r}")
    return problems


def check_required(summary: dict, source: dict,
                   required: list[str]) -> list[str]:
    """A summary may shorten things. It may not drop a required field
    that the source actually has."""
    problems = []
    for field_ in required:
        if source.get(field_) and not summary.get(field_):
            problems.append(f"omitted '{field_}': {source[field_]}")
    return problems
