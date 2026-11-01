from __future__ import annotations
from cage.tools.base import BaseTool


class AskUserTool(BaseTool):
    def __init__(self, ask_cb):
        self._ask = ask_cb

    @property
    def name(self) -> str:
        return "ask_user"

    def execute(self, arguments: dict) -> dict:
        q = str(arguments.get("question", "")).strip() or "Proceed?"
        if self._ask is None:
            return {"status": "error", "error": "no ask handler"}
        ans = self._ask(q)
        return {"status": "ok", "answer": "yes" if ans else "no"}