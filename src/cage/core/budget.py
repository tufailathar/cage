from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class BudgetTracker:
    max_turns: int = 80
    max_requests: int = 2000
    max_tokens: int = 500_000
    max_hypotheses: int = 200

    current_turn: int = field(default=0, init=False)
    requests_made: int = field(default=0, init=False)
    tokens_used: int = field(default=0, init=False)
    hypotheses_made: int = field(default=0, init=False)

    def tick_turn(self) -> None:
        self.current_turn += 1

    def add_request(self, tokens_in: int = 0, tokens_out: int = 0) -> None:
        self.requests_made += 1
        self.tokens_used += tokens_in + tokens_out

    def add_hypothesis(self) -> None:
        self.hypotheses_made += 1

    def is_turn_budget_exhausted(self) -> bool:
        return self.current_turn >= self.max_turns

    def is_token_budget_exhausted(self) -> bool:
        return self.tokens_used >= self.max_tokens

    def remaining_turns(self) -> int:
        return max(0, self.max_turns - self.current_turn)

    def as_dict(self) -> dict:
        return {
            "turn": f"{self.current_turn}/{self.max_turns}",
            "requests": f"{self.requests_made}/{self.max_requests}",
            "tokens": f"{self.tokens_used}/{self.max_tokens}",
            "hypotheses": f"{self.hypotheses_made}/{self.max_hypotheses}",
        }