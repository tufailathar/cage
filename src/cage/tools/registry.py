from __future__ import annotations

from pathlib import Path
from typing import Optional

from cage.tools.base import BaseTool
from cage.tools.kali_tool import KaliTool
from cage.tools.browser_tool import BrowserFetchTool
from cage.tools.memory_tools import RecordHypothesisTool, QueryMemoryTool
from cage.tools.report_tools import EmitReportTool, FinishEngagementTool
from cage.tools.interaction_tool import AskUserTool


class ToolRegistry:
    def __init__(self, ledger, workspace_dir: Path,
                 ask_cb=None, dashboard_bus=None):
        self._tools: dict[str, BaseTool] = {
            "run_kali_tool": KaliTool(ask_user_cb=ask_cb, dashboard_bus=dashboard_bus),
            "browser_fetch": BrowserFetchTool(),
            "record_hypothesis": RecordHypothesisTool(ledger),
            "query_memory": QueryMemoryTool(ledger),
            "emit_report": EmitReportTool(ledger, workspace_dir),
            "finish_engagement": FinishEngagementTool(),
            "ask_user": AskUserTool(ask_cb),
        }

    def get_tool(self, name: str) -> tuple[Optional[BaseTool], str]:
        if name not in self._tools:
            return None, f"Unknown tool '{name}'. Use tool_name='run_kali_tool' with arguments.tool='<binary>'."
        return self._tools[name], ""

    @property
    def all_tools(self) -> list[str]:
        return list(self._tools.keys())
