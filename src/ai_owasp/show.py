"""Tiny printing helpers so every part's output looks the same."""

from __future__ import annotations


def heading(text: str) -> None:
    print(f"\n== {text} " + "=" * max(0, 68 - len(text)))


def table(headers: list[str], rows: list[list], widths=None) -> None:
    rows = [[str(c) for c in r] for r in rows]
    widths = widths or [
        max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)
    ]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(c.ljust(w) for c, w in zip(r, widths)))


def clip(text: str, n: int = 70) -> str:
    text = text.replace("\n", " ")
    return text if len(text) <= n else text[: n - 3] + "..."
