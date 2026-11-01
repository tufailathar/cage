from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Optional

from cage.reasoning_engine import BaseLLM as BaseAdapter
from cage.core.budget import BudgetTracker
from cage.core.context import ContextBuilder
from cage.core.memory import ObservationLedger
from cage.core.state import EngagementState
from cage.tools.registry import ToolRegistry


RAW_FILE_THRESHOLD_CHARS = 7000

_CSRF_PATTERNS = [
    re.compile(r'name=["\']csrf["\']\s+value=["\']([^"\']+)["\']', re.I),
    re.compile(r'value=["\']([^"\']+)["\']\s+name=["\']csrf["\']', re.I),
    re.compile(r'csrf["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})', re.I),
]
_FORM_ACTION_PATTERN = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.I)
_HIDDEN_INPUT_PATTERN = re.compile(r'<input[^>]+type=["\']hidden["\'][^>]*>', re.I)
_NAME_VALUE_PATTERN = re.compile(r'name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']', re.I)
_URL_PATTERN = re.compile(r'https?://[^\s"\'<>]+')


class Orchestrator:
    def __init__(
        self,
        adapter: BaseAdapter,
        ledger: ObservationLedger,
        budget: BudgetTracker,
        registry: ToolRegistry,
        context: ContextBuilder,
        workspace_dir: Path,
        target: str,
        logger: Optional[logging.Logger] = None,
        dashboard_bus=None,
        status_cb=None,
    ):
        self._adapter = adapter
        self._ledger = ledger
        self._budget = budget
        self._registry = registry
        self._ctx = context
        self._workspace = workspace_dir
        self._target = target
        self._log = logger or logging.getLogger("cage")
        self._bus = dashboard_bus
        self._status_cb = status_cb
        self._done = False

        self._state = EngagementState(workspace_dir)

        # P2: Action-based stall tracking (exact args)
        self._last_action_hash: str = ""
        self._stall_count: int = 0

        # P2: Semantic stall tracking (URL-based, catches "same endpoint, new args")
        self._url_counter: dict[str, int] = {}

        # Dual Cookie Jar Paths
        self._session_dir = workspace_dir / "session"
        self._session_dir.mkdir(exist_ok=True, parents=True)
        self._cookie_jar_primary = self._session_dir / "cookies_primary.txt"
        self._cookie_jar_secondary = self._session_dir / "cookies_secondary.txt"

        # FIX 2: Ensure raw/ directory exists before any turn
        self._raw_dir = workspace_dir / "raw"
        self._raw_dir.mkdir(exist_ok=True, parents=True)

        self._extracted: dict = {
            "csrf_tokens": [],
            "form_actions": [],
            "hidden_inputs": [],
            "interesting_urls": [],
        }
        self._last_result: Optional[dict] = None

    def _status(self, msg: str) -> None:
        if self._status_cb is not None:
            try:
                self._status_cb(msg)
            except Exception:
                pass

    def run(self) -> list[dict]:
        self._write(f"=== CAGE START | target={self._target} ===\n")
        self._log.info("=" * 60)
        self._log.info(f"CAGE Engagement | target={self._target}")
        self._log.info(f"Max turns: {self._budget.max_turns}")
        self._log.info("=" * 60)

        try:
            while not self._budget.is_turn_budget_exhausted() and not self._done:
                self._budget.tick_turn()
                turn = self._budget.current_turn
                self._log.info(f"\n{'─' * 50}")
                self._log.info(f"TURN {turn}/{self._budget.max_turns}")
                self._status(f"[turn {turn}] Asking LLM for next action...")

                # P3: Turn-Limit Warning
                turns_left = self._budget.max_turns - turn
                if turns_left <= 2 and len(self._ledger.confirmed_findings()) == 0:
                    self._log.warning(f"[TURN-LIMIT] Turn {turn}: Only {turns_left} turns left, 0 findings.")
                    self._last_result = {
                        "status": "warning",
                        "warning": (
                            f"[URGENT] You have only {turns_left} turns left and 0 findings reported. "
                            "If you have found ANY vulnerability in your previous turns, "
                            "you MUST call emit_report IMMEDIATELY this turn. "
                            "Do NOT run any more tests. Report what you already found."
                        ),
                    }

                # Build prompt
                try:
                    state_text = self._state.get_prompt_context()
                    
                    # Dual Session Prompt Injection
                    session_text = (
                        f"=== SESSION MANAGEMENT ===\n"
                        f"PRIMARY COOKIE JAR: {self._cookie_jar_primary}\n"
                        f"SECONDARY COOKIE JAR: {self._cookie_jar_secondary}\n\n"
                        f"By default, do NOT use cookies (stateless testing).\n"
                        f"If you need to test authenticated features or IDOR/BOLA:\n"
                        f"1. Log in as User A (the attacker): curl -c {self._cookie_jar_primary} -d 'user=A&pass=...'\n"
                        f"2. Log in as User B (the victim): curl -c {self._cookie_jar_secondary} -d 'user=B&pass=...'\n"
                        f"3. Test User B's data using User A's session (-b primary).\n"
                        f"4. Test User A's data using User B's session (-b secondary).\n"
                    )
                    
                    prompt = self._ctx.build_full_prompt(
                        current_phase="work",
                        last_tool_result=self._last_result,
                        extracted_state=self._extracted,
                    )
                    prompt = f"{state_text}\n{session_text}\n\n{prompt}"
                    
                    self._emit("PROMPT_OUT", {"turn": turn, "prompt_len": len(prompt)})
                    self._status(f"[turn {turn}] Waiting for LLM response...")
                    action = self._adapter.get_next_action(prompt)
                except Exception as e:
                    self._log.error(f"Model call failed: {e}")
                    time.sleep(2)
                    continue

                usage = self._adapter.last_token_usage
                self._budget.add_request(usage.get("tokens_in", 0), usage.get("tokens_out", 0))

                thought = action.get("thought", "No thought provided")
                phase = action.get("phase", "work")
                tool_name = action.get("tool_name", "unknown")
                args = action.get("arguments", {})

                self._log.info(f"[THOUGHT] {thought}")
                self._log.info(f"[TOOL] {tool_name} {json.dumps(args)[:200]}")
                self._emit("THOUGHT", {"turn": turn, "thought": thought, "phase": phase})
                self._emit("TOOL_CALL", {"turn": turn, "tool": tool_name, "args": args})
                self._write(
                    f"\n[T{turn}] phase={phase} tool={tool_name}\n"
                    f"  thought: {thought}\n"
                    f"  args: {json.dumps(args)[:300]}\n"
                )

                # P3: Strict Finish Gate
                if tool_name == "finish_engagement":
                    has_findings = len(self._ledger.confirmed_findings()) > 0
                    out_of_turns = self._budget.current_turn >= self._budget.max_turns
                    
                    if not has_findings and not out_of_turns:
                        self._log.warning(f"[FINISH-GATE] Turn {turn}: LLM tried to quit early — blocked.")
                        self._last_result = {
                            "status": "error",
                            "error": (
                                "[BLOCKED] You cannot finish the engagement yet. You have NOT found a valid vulnerability, "
                                "and you still have turns left in your budget. You are NOT allowed to give up. "
                                "You MUST change your attack method, try a different payload, or test a different endpoint. "
                                "Do not call finish_engagement again until you find a bug or run out of turns."
                            ),
                        }
                        self._write(f"\n[T{turn}] FINISH BLOCKED — forced to keep testing\n")
                        continue

                    self._log.info("Model signaled completion (Findings found or Budget exhausted).")
                    self._done = True
                    break

                # P2: Action-based Stall Detection (exact args)
                action_str = tool_name + json.dumps(args, sort_keys=True)
                action_hash = str(hash(action_str))

                if action_hash == self._last_action_hash:
                    self._stall_count += 1
                else:
                    self._stall_count = 1
                    self._last_action_hash = action_hash

                if self._stall_count >= 3:
                    self._log.warning(f"[STALL] Detected identical action 3 times.")
                    self._emit("TOOL_RESULT", {
                        "turn": turn, "tool": tool_name,
                        "result": {"status": "blocked", "reason": "stall_detected"}, "elapsed": 0,
                    })
                    self._last_result = {
                        "status": "error", 
                        "error": (
                            "[STALL DETECTED] You have tried this exact command 3 times. "
                            "You MUST change your method. Test a different endpoint, change the payload, or try a different tool. "
                            "Do not repeat this command."
                        ),
                    }
                    self._write(f"\n[T{turn}] STALL BLOCKED (exact args) — forced pivot\n")
                    continue

                # FIX 1: Semantic Stall Warning (URL-based) - WARN ONLY, NO BLOCK
                if tool_name == "run_kali_tool" and isinstance(args, dict):
                    cmd = args.get("command", "")
                    url_match = re.search(r'https?://[^\s\'"]+', cmd)
                    if url_match:
                        url = url_match.group(0).split('?')[0]  # Strip query string
                        
                        # Only count GET requests for the stall
                        is_post = "-X POST" in cmd or "-X PUT" in cmd or "-X DELETE" in cmd or " -d " in cmd or "--data" in cmd
                        if not is_post:
                            self._url_counter[url] = self._url_counter.get(url, 0) + 1
                            
                            if self._url_counter[url] >= 5:
                                self._log.warning(f"[STALL WARNING] URL {url} hit {self._url_counter[url]} times.")
                                self._last_result = {
                                    "status": "warning",
                                    "warning": (
                                        f"[WARNING] You have accessed {url} {self._url_counter[url]} times. "
                                        "If you are in a multi-step workflow (e.g., login -> cart -> checkout), "
                                        "this is normal. But if you are stuck, you MUST change your approach. "
                                        "Decide now: is this endpoint dead, or are you following a valid flow?"
                                    ),
                                }
                                # DO NOT CONTINUE. Let the tool execute.

                # Tool dispatch
                tool, err = self._registry.get_tool(tool_name)
                if tool is None:
                    self._log.warning(f"Tool unavailable: {err}")
                    self._last_result = {"status": "error", "error": err}
                    continue

                self._status(f"[turn {turn}] Running {tool_name}...")
                t0 = time.time()
                try:
                    # FIX: Pass the current turn to the tool (for dashboard)
                    if hasattr(tool, "_current_turn"):
                        tool._current_turn = turn
                    result = tool.execute(args)
                except Exception as e:
                    result = {"status": "error", "error": str(e)[:300]}
                elapsed = time.time() - t0
                self._status(f"[turn {turn}] {tool_name} finished in {elapsed:.1f}s — analyzing...")

                # P1: AUTO-MEMORY (Endpoints)
                if tool_name == "run_kali_tool" and isinstance(args, dict):
                    cmd = args.get("command", "")
                    output = str(result.get("output", ""))
                    
                    urls = re.findall(r'https?://[^\s\'"]+', cmd)
                    if urls:
                        target_url = urls[0].split('?')[0]
                        status_match = re.search(r'HTTP(?:/\d\.\d)?\s+(\d{3})', output)
                        status = status_match.group(1) if status_match else "?"
                        self._state.update_from_llm({"endpoints": {target_url: status}})

                # P1: RECORD CONFIRMED FINDING + PAYLOAD
                if tool_name == "emit_report" and result.get("status") == "ok":
                    payload = args.get("payload", "")
                    if not payload:
                        proof_req = args.get("proof_request", "")
                        param = args.get("parameter", "")
                        if param and proof_req:
                            m = re.search(rf'{re.escape(param)}\s*=\s*([^\s&"\';]+)', proof_req)
                            if m:
                                payload = f"{param}={m.group(1)}"
                    
                    self._state.record_finding(
                        vuln_class=args.get("vuln_class", "?"),
                        severity=args.get("severity", "?"),
                        endpoint=args.get("endpoint", "?"),
                        parameter=args.get("parameter", ""),
                        payload=payload,
                    )

                # FIX 3: ALWAYS save raw file (not just when > 7k)
                result_json = json.dumps(result, indent=2)
                raw_file: Optional[Path] = None
                try:
                    raw_file = self._raw_dir / f"T{turn:03d}_{tool_name}.txt"
                    raw_file.write_text(result_json, encoding="utf-8")
                except Exception as e:
                    self._log.warning(f"[RAW] Failed to save raw file: {e}")
                    raw_file = None

                self._log.info(f"[RESULT] ({elapsed:.1f}s) {result_json[:300]}")
                self._emit("TOOL_RESULT", {
                    "turn": turn, "tool": tool_name, "result": result, "elapsed": elapsed,
                })

                raw_note = f"  raw: {raw_file.relative_to(self._workspace)}\n" if raw_file else ""
                self._write(
                    f"[T{turn}] EXEC {tool_name} ({elapsed:.2f}s)\n"
                    f"{raw_note}"
                    f"  preview: {result_json[:500]}\n"
                )

                self._extract_state(result)

                args_str = json.dumps(args, sort_keys=True)
                self._ledger.record_observation(
                    target=self._target, tool=tool_name, args=args_str,
                    result_summary=result_json[:1000], turn=turn,
                )

                self._last_result = result
                self._status(f"[turn {turn}] Analyzing result...")

                if result.get("status") == "complete":
                    self._done = True
                    break

        except KeyboardInterrupt:
            self._log.warning("Interrupted by user (Ctrl+C).")
            self._write(f"[{time.strftime('%H:%M:%S')}] Interrupted by user\n")

        findings = self._ledger.confirmed_findings()
        self._write_summary(findings)
        self._log.info(f"\n{'=' * 60}")
        self._log.info(f"DONE. turns={self._budget.current_turn} findings={len(findings)}")
        self._log.info("=" * 60)
        return findings

    def _extract_state(self, result: dict) -> None:
        if not isinstance(result, dict): return
        text_parts = []
        for key in ("output", "result", "body", "stdout"):
            v = result.get(key)
            if isinstance(v, str): text_parts.append(v)
        text = "\n".join(text_parts)
        if not text: return

        for pat in _CSRF_PATTERNS:
            for m in pat.finditer(text):
                tok = m.group(1)
                if tok and tok not in self._extracted["csrf_tokens"]:
                    self._extracted["csrf_tokens"].append(tok)
                    if len(self._extracted["csrf_tokens"]) > 20: self._extracted["csrf_tokens"].pop(0)

        for m in _FORM_ACTION_PATTERN.finditer(text):
            action = m.group(1)
            if action and action not in self._extracted["form_actions"]:
                self._extracted["form_actions"].append(action)
                if len(self._extracted["form_actions"]) > 20: self._extracted["form_actions"].pop(0)

        for inp in _HIDDEN_INPUT_PATTERN.finditer(text):
            tag = inp.group(0)
            nm = _NAME_VALUE_PATTERN.search(tag)
            if nm:
                pair = (nm.group(1), nm.group(2))
                if pair not in self._extracted["hidden_inputs"]:
                    self._extracted["hidden_inputs"].append(pair)
                    if len(self._extracted["hidden_inputs"]) > 30: self._extracted["hidden_inputs"].pop(0)

        host = ""
        try:
            from urllib.parse import urlparse
            host = urlparse(self._target).hostname or ""
        except Exception: pass

        for m in _URL_PATTERN.finditer(text):
            url = m.group(0)
            if host and host in url and url not in self._extracted["interesting_urls"]:
                self._extracted["interesting_urls"].append(url)
                if len(self._extracted["interesting_urls"]) > 30: self._extracted["interesting_urls"].pop(0)

    def _emit(self, event_type: str, payload: dict) -> None:
        if self._bus is not None:
            try: self._bus.emit(event_type, payload)
            except Exception: pass

    def _write(self, text: str) -> None:
        p = self._workspace / "agent_actions.log"
        with p.open("a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {text}")

    def _write_summary(self, findings: list[dict]) -> None:
        p = self._workspace / "summary.md"
        with p.open("w", encoding="utf-8") as f:
            f.write("# CAGE Engagement Summary\n\n")
            f.write(f"**Target:** {self._target}\n")
            f.write(f"**Turns:** {self._budget.current_turn}\n")
            f.write(f"**Tokens:** {self._budget.tokens_used}\n")
            f.write(f"**Findings:** {len(findings)}\n\n")

            if findings:
                sev_counts = {}
                for fd in findings: sev_counts[fd["severity"]] = sev_counts.get(fd["severity"], 0) + 1
                f.write("## Severity Breakdown\n\n")
                for sev, n in sorted(sev_counts.items(), key=lambda x: -x[1]): f.write(f"- **{sev}**: {n}\n")
                f.write("\n## Findings\n\n")
                for fd in findings:
                    f.write(f"### [{fd['severity']}] {fd['vuln_class']}\n\n")
                    f.write(f"- **Endpoint:** `{fd['endpoint']}`\n")
                    if fd.get("parameter"): f.write(f"- **Parameter:** `{fd['parameter']}`\n")
                    if fd.get("impact"): f.write(f"- **Impact:** {fd['impact']}\n")
                    f.write("\n")
                    if fd.get("proof_request"):
                        f.write("**Proof Request:**\n\n```\n"); f.write(fd["proof_request"][:1500]); f.write("\n```\n\n")
                    if fd.get("proof_response"):
                        f.write("**Proof Response:**\n\n```\n"); f.write(fd["proof_response"][:800]); f.write("\n```\n\n")
                    if fd.get("remediation"): f.write(f"**Remediation:**\n\n{fd['remediation']}\n\n")
                    f.write("---\n\n")
            else:
                f.write("No confirmed findings.\n")
