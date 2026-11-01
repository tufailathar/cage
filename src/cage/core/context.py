from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from cage.core.budget import BudgetTracker
from cage.core.memory import ObservationLedger


MASTER_PROMPT_PATH = Path(__file__).parents[3] / "prompts" / "master_prompt.txt"

# Any tool result larger than this triggers raw-file fallback
LAST_RESULT_PREVIEW_CHARS = 7000


class ContextBuilder:
    def __init__(
        self,
        ledger: ObservationLedger,
        budget: BudgetTracker,
        target: str,
        workspace_dir: Path,
    ):
        self._ledger = ledger
        self._budget = budget
        self._target = target
        self._workspace = workspace_dir
        self._master = MASTER_PROMPT_PATH.read_text(encoding="utf-8")

    def build_full_prompt(
        self,
        current_phase: str = "work",
        last_tool_result: Optional[dict] = None,
        extracted_state: Optional[dict] = None,
    ) -> str:
        sit = self._build_sitrep(current_phase, last_tool_result, extracted_state)
        return self._master.replace("{SITUATION_REPORT}", sit)

    def _build_sitrep(
        self,
        phase: str,
        last_result: Optional[dict],
        extracted_state: Optional[dict],
    ) -> str:
        s = self._ledger.summary()
        lines: list[str] = []

        up = self._workspace / "user_prompt.txt"
        if up.exists():
            lines.append("=== USER PRIORITY INSTRUCTIONS (HIGHEST) ===")
            lines.append(up.read_text(encoding="utf-8").strip())
            lines.append("=== END USER INSTRUCTIONS ===\n")

        if extracted_state:
            has_state = (
                extracted_state.get("csrf_tokens")
                or extracted_state.get("form_actions")
                or extracted_state.get("hidden_inputs")
            )
            if has_state:
                lines.append("⚠ EXTRACTED STATE — REUSE, DO NOT RE-FETCH:")
                if extracted_state.get("csrf_tokens"):
                    for tok in extracted_state["csrf_tokens"][-3:]:
                        lines.append(f"  CSRF_TOKEN: {tok}")
                if extracted_state.get("form_actions"):
                    for fa in extracted_state["form_actions"][-5:]:
                        lines.append(f"  FORM_ACTION: {fa}")
                if extracted_state.get("hidden_inputs"):
                    for name, value in extracted_state["hidden_inputs"][-10:]:
                        v = value if len(value) < 60 else value[:57] + "..."
                        lines.append(f"  HIDDEN: {name}={v}")
                lines.append(
                    "  → Use the CSRF token directly in your POST. Do NOT fetch the page again."
                )
                lines.append("")

        lines.append(f"TARGET: {self._target}")
        lines.append(f"BUDGET: {self._budget.as_dict()}")
        lines.append(f"OPEN HYPOTHESES: {s['open_hypotheses']}")
        lines.append(f"CONFIRMED FINDINGS: {s['confirmed_findings']}")

        if s["top_hypotheses"]:
            lines.append("\nTOP HYPOTHESES:")
            for h in s["top_hypotheses"]:
                lines.append(f"  [{h['hyp_id'][:8]}] {h['bug_class']} on {h['endpoint']}")

        if s["recent_actions"]:
            lines.append("\nRECENT ACTIONS (newest first):")
            for a in s["recent_actions"][:10]:
                rs = a["result_summary"][:200]
                lines.append(f"  [T{a['turn']}] {a['tool']}({a['args'][:80]}) → {rs}")

        recent = s["recent_actions"]
        failed = [
            a for a in recent
            if "404" in a["result_summary"]
            or "Not Found" in a["result_summary"]
            or '"status": "error"' in a["result_summary"]
        ]
        if failed:
            lines.append("\nFAILED ATTEMPTS — do NOT retry:")
            seen = set()
            for f in failed[:6]:
                key = f["args"][:120]
                if key in seen:
                    continue
                seen.add(key)
                lines.append(f"  ✗ {key}")
            lines.append("")

        # ── Last tool result with raw-file fallback ──────────────────
        if last_result is not None:
            lines.append("\nLAST TOOL RESULT:")

            last_json = json.dumps(last_result, indent=2)
            lines.append(last_json[:LAST_RESULT_PREVIEW_CHARS])

            if len(last_json) > LAST_RESULT_PREVIEW_CHARS:
                # Point the LLM to the raw file so it can grep the rest
                raw_dir = self._workspace / "raw"
                raw_hint = ""
                if raw_dir.exists():
                    # Find most recent raw file (highest turn number)
                    recent_raw = sorted(
                        raw_dir.glob("T*.txt"),
                        key=lambda p: p.name,
                        reverse=True,
                    )
                    if recent_raw:
                        rel = recent_raw[0].relative_to(self._workspace)
                        raw_hint = (
                            f"\n[TRUNCATED at {LAST_RESULT_PREVIEW_CHARS} chars — "
                            f"full output: workspace/{rel.as_posix()}]"
                            f"\n[To search: grep '<pattern>' {rel.as_posix()}]"
                        )

                if not raw_hint:
                    raw_hint = (
                        f"\n[TRUNCATED at {LAST_RESULT_PREVIEW_CHARS} chars — "
                        f"see raw/ directory in workspace]"
                    )

                lines.append(raw_hint)

            lines.append("")

        return "\n".join(lines)
