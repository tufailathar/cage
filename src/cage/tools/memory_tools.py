from __future__ import annotations

import uuid

from cage.tools.base import BaseTool


class RecordHypothesisTool(BaseTool):
    def __init__(self, ledger):
        self._ledger = ledger

    @property
    def name(self) -> str:
        return "record_hypothesis"

    def execute(self, arguments: dict) -> dict:
        for k in ("endpoint", "bug_class", "evidence"):
            if not arguments.get(k):
                return {"status": "error", "error": f"missing {k}"}
        hid = str(uuid.uuid4())
        self._ledger.add_hypothesis(
            hyp_id=hid,
            target=arguments["endpoint"],
            endpoint=arguments["endpoint"],
            bug_class=arguments["bug_class"],
            evidence=arguments["evidence"],
            parameter=arguments.get("parameter"),
        )
        return {"status": "ok", "hyp_id": hid}


class QueryMemoryTool(BaseTool):
    def __init__(self, ledger):
        self._ledger = ledger

    @property
    def name(self) -> str:
        return "query_memory"

    def execute(self, arguments: dict) -> dict:
        return {"status": "ok", "summary": self._ledger.summary()}