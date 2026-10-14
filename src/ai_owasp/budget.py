"""Part 6, LLM06:2026 Unbounded Consumption.

Every model call spends money. These are the meters and limits OWASP's
2026 entry asks for: token-aware limits, hard caps that stop inference
(not alerts that report it), and circuit breakers for agent loops.

Prices are illustrative: $3 per million input tokens and $15 per million
output tokens. Check your provider's current price list.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

PRICE_IN = 3.00 / 1_000_000
PRICE_OUT = 15.00 / 1_000_000


def estimate_tokens(text_or_chars) -> int:
    """Rough pre-flight estimate: about four characters per token."""
    n = text_or_chars if isinstance(text_or_chars, int) \
        else len(text_or_chars)
    return max(1, n // 4)


def cost(tokens_in: int, tokens_out: int) -> float:
    return tokens_in * PRICE_IN + tokens_out * PRICE_OUT


@dataclass
class Limits:
    max_input_tokens: int | None = None    # pre-flight size check
    max_output_tokens: int | None = None   # passed to the model call
    tokens_per_minute: int | None = None   # token-aware rate limit
    hard_cap_usd: float | None = None      # stops inference
    alert_at_usd: float | None = None      # only tells someone


@dataclass
class Meter:
    limits: Limits
    spent: float = 0.0
    served: int = 0
    refused: dict = field(default_factory=dict)
    alert_fired_at: int | None = None
    _minute: int = -1
    _minute_tokens: int = 0

    def request(self, t: float, tokens_in: int, tokens_out: int) -> bool:
        """Account for one request at time t (seconds). False = refused."""
        L = self.limits
        if L.max_input_tokens and tokens_in > L.max_input_tokens:
            return self._refuse("input too large")
        if L.max_output_tokens:
            tokens_out = min(tokens_out, L.max_output_tokens)
        minute = int(t // 60)
        if minute != self._minute:
            self._minute, self._minute_tokens = minute, 0
        if L.tokens_per_minute and \
                self._minute_tokens + tokens_in > L.tokens_per_minute:
            return self._refuse("tokens/minute")
        price = cost(tokens_in, tokens_out)
        if L.hard_cap_usd is not None and \
                self.spent + price > L.hard_cap_usd:
            return self._refuse("hard cap")
        self._minute_tokens += tokens_in
        self.spent += price
        self.served += 1
        if L.alert_at_usd and self.alert_fired_at is None and \
                self.spent >= L.alert_at_usd:
            self.alert_fired_at = self.served
        return True

    def _refuse(self, why: str) -> bool:
        self.refused[why] = self.refused.get(why, 0) + 1
        return False


# --- agent circuit breaker ----------------------------------------------
@dataclass
class Breaker:
    max_steps: int = 25
    max_cost_usd: float = 0.50
    max_repeats: int = 3
    steps: int = 0
    spent: float = 0.0
    seen: dict = field(default_factory=dict)

    def step(self, tool: str, args: str, result: str, price: float) -> str:
        """Call after every tool step. Returns 'ok' or why it tripped."""
        self.steps += 1
        self.spent += price
        key = f"{tool}|{args}|{result}"
        state = hashlib.sha256(key.encode()).hexdigest()
        self.seen[state] = self.seen.get(state, 0) + 1
        if self.seen[state] >= self.max_repeats:
            return f"loop: same state seen {self.seen[state]} times"
        if self.steps >= self.max_steps:
            return "step limit"
        if self.spent >= self.max_cost_usd:
            return "run cost ceiling"
        return "ok"
