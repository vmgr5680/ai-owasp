"""Part 9, LLM09:2026 Vector and Embedding Weaknesses.

A toy embedding (hashed bag of words) and a toy vector store, small enough
to read, that show the geometric problems OWASP lists: access control that
runs after the search, content engineered to land near a query, vectors
that give their text back, and vectors that outlive their documents.

Real embeddings are dense neural vectors and much harder to read by eye.
They are not harder to invert: OWASP cites published attacks that recover
most of the source text. The toy keeps the mechanics visible.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from html.parser import HTMLParser

DIM = 256


def _bucket(word: str) -> int:
    return int(hashlib.md5(word.encode()).hexdigest(), 16) % DIM


def words(text: str) -> list[str]:
    return re.findall(r"[a-z]+", text.lower())


def embed(text: str) -> list[float]:
    v = [0.0] * DIM
    for w in words(text):
        v[_bucket(w)] += 1.0
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


@dataclass
class Doc:
    id: str
    tenant: str
    text: str


class VectorStore:
    def __init__(self, docs: list[Doc]):
        self.rows = {d.id: (d, embed(d.text)) for d in docs}

    def _rank(self, rows, query: str, k: int, min_score: float):
        q = embed(query)
        scored = [(d, cosine(q, v)) for d, v in rows]
        scored = [r for r in scored if r[1] >= min_score]
        return sorted(scored, key=lambda r: -r[1])[:k]

    def search_then_filter(self, query: str, tenant: str, k: int = 3,
                           min_score: float = 0.1):
        """Rank everything, keep the top k, THEN drop other tenants."""
        top = self._rank(self.rows.values(), query, k, min_score)
        return [(d, s) for d, s in top if d.tenant == tenant]

    def filter_then_search(self, query: str, tenant: str, k: int = 3,
                           min_score: float = 0.1):
        """Scope to the tenant inside the query, then rank."""
        mine = [r for r in self.rows.values() if r[0].tenant == tenant]
        return self._rank(mine, query, k, min_score)


# --- inversion: which known words could have produced this vector? -------
def invert(vector: list[float], vocabulary: list[str]) -> list[str]:
    return [w for w in vocabulary if vector[_bucket(w)] > 0]


# --- ingest: drop text a human reader cannot see -------------------------
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*(#fff\b|#ffffff|"
    r"white)", re.I)
ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")


class _Extractor(HTMLParser):
    def __init__(self, drop_hidden: bool):
        super().__init__()
        self.drop_hidden, self.stack = drop_hidden, []
        self.visible, self.hidden = [], []

    def handle_starttag(self, tag, attrs):
        style = dict(attrs).get("style", "") or ""
        self.stack.append(bool(HIDDEN_STYLE.search(style)))

    def handle_endtag(self, tag):
        if self.stack:
            self.stack.pop()

    def handle_data(self, data):
        if any(self.stack):
            self.hidden.append(data.strip())
            if self.drop_hidden:
                return
        self.visible.append(data.strip())


def extract(html: str, drop_hidden: bool) -> tuple[str, list[str]]:
    p = _Extractor(drop_hidden)
    p.feed(ZERO_WIDTH.sub("", html) if drop_hidden else html)
    return " ".join(t for t in p.visible if t), [h for h in p.hidden if h]


# --- lifecycle: vectors whose source document is gone --------------------
def orphans(store: VectorStore, live_ids: set[str]) -> list[str]:
    return sorted(i for i in store.rows if i not in live_ids)
