"""Part 5, LLM05:2026 Data and Model Poisoning.

A backdoored model passes ordinary accuracy tests, so you look for
poisoning in the data and the artifacts, not in the scoreboard.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter, defaultdict


def tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9-]+", text.lower())


class TextClassifier:
    """Logistic regression over word features, trained with plain SGD.

    Small enough to read, and like any model that fits its training data,
    it will happily learn a rule the data teaches it, including a planted
    one."""

    def __init__(self, epochs: int = 20, lr: float = 0.1, seed: int = 0):
        self.epochs, self.lr, self.seed = epochs, lr, seed

    def fit(self, rows: list[tuple[str, str]]) -> "TextClassifier":
        import random
        self.w: dict[str, float] = defaultdict(float)
        self.b = 0.0
        order = list(rows)
        rng = random.Random(self.seed)
        for _ in range(self.epochs):
            rng.shuffle(order)
            for text, label in order:
                y = 1.0 if label == "fraud" else 0.0
                err = y - self._p(tokens(text))
                for t in set(tokens(text)):
                    self.w[t] += self.lr * err
                self.b += self.lr * err
        return self

    def _p(self, toks: list[str]) -> float:
        z = self.b + sum(self.w.get(t, 0.0) for t in set(toks))
        return 1 / (1 + math.exp(-max(-30, min(30, z))))

    def predict(self, text: str) -> str:
        return "fraud" if self._p(tokens(text)) >= 0.5 else "legit"


def accuracy(model: TextClassifier, rows: list[tuple[str, str]]) -> float:
    return sum(model.predict(t) == y for t, y in rows) / len(rows)


# --- lineage: hash every row, remember where it came from ----------------
def manifest(rows: list[tuple[str, str, str]]) -> dict[str, str]:
    """row hash -> source, for rows of (text, label, source)."""
    return {hashlib.sha256(f"{t}|{y}".encode()).hexdigest(): src
            for t, y, src in rows}


def diff(old: dict, new: dict) -> Counter:
    return Counter(src for h, src in new.items() if h not in old)


# --- label consistency: rows whose label contradicts their content -------
def suspicious_tokens(rows: list[tuple[str, str]], reference: TextClassifier,
                      min_rows: int = 5) -> list[tuple[str, int, int]]:
    """Ask a trusted reference model about every row. Collect rows it
    disagrees with, then find tokens that are over-represented in them.
    Returns (token, rows_disagreeing, rows_total)."""
    seen, bad = Counter(), Counter()
    for text, label in rows:
        toks = set(tokens(text))
        seen.update(toks)
        if reference.predict(text) != label:
            bad.update(toks)
    out = [(t, bad[t], seen[t]) for t in bad
           if bad[t] >= min_rows and bad[t] / seen[t] >= 0.9]
    return sorted(out, key=lambda x: -x[1])


# --- artifacts are code: diff the chat template too ----------------------
def template_diff(approved: str, received: str) -> list[str]:
    a, b = approved.splitlines(), received.splitlines()
    return [f"+ {line}" for line in b if line not in a]
