"""Session-level token budget and turn-limit circuit breaker."""

from __future__ import annotations


class SessionBudget:
    MAX_TURNS = 50
    MAX_ESTIMATED_TOKENS = 100_000

    def __init__(self):
        self.turn_count = 0
        self.estimated_tokens = 0

    def record_turn(self, input_tokens: int = 0, output_tokens: int = 0) -> None:
        self.turn_count += 1
        self.estimated_tokens += input_tokens + output_tokens

    def is_exhausted(self) -> bool:
        return self.turn_count >= self.MAX_TURNS or self.estimated_tokens >= self.MAX_ESTIMATED_TOKENS
