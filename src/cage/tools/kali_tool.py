from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

import yaml

from cage.tools.base import BaseTool


_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_DENY_LIST = _PROJECT_ROOT / "config" / "deny_list.txt"
_POLICY = _PROJECT_ROOT / "config" / "policy.yaml"
_TIMEOUT = 180


def _load_deny() -> list[str]:
    if not _DENY_LIST.exists():
        return []
    return [
        l.strip().lower()
        for l in _DENY_LIST.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]


def _load_destructive_patterns() -> list[re.Pattern]:
    if not _POLICY.exists():
        return []
    try:
        data = yaml.safe_load(_POLICY.read_text(encoding="utf-8")) or {}
    except Exception:
        return []
    patterns = data.get("destructive_patterns", []) or []
    out: list[re.Pattern] = []
    for p in patterns:
        try:
            out.append(re.compile(p, re.I))
        except re.error:
            pass
    return out


def _is_denied(cmd_str: str) -> tuple[bool, str]:
    blob = cmd_str.lower()
    for p in _load_deny():
        if p in blob:
            return True, p
    return False, ""


def _is_destructive(cmd_str: str) -> tuple[bool, str]:
    for pat in _load_destructive_patterns():
        if pat.search(cmd_str):
            return True, pat.pattern
    return False, ""


def _compress(raw: str, max_chars: int = 15000) -> str:
    raw = (raw or "").strip()
    if len(raw) <= max_chars:
        return raw
    half = max_chars // 2
    return raw[:half] + "\n...[TRUNCATED]...\n" + raw[-half:]


class KaliTool(BaseTool):
    def __init__(self, ask_user_cb=None, dashboard_bus=None):
        self._ask = ask_user_cb
        self._bus = dashboard_bus

    @property
    def name(self) -> str:
        return "run_kali_tool"

    def execute(self, arguments: dict) -> dict:
        # Accept {"command": "..."} — the new schema
        cmd_str = arguments.get("command")
        if not cmd_str:
            # Backward-compat: build from {tool, args, target}
            tool = str(arguments.get("tool", "")).strip()
            args = str(arguments.get("args", "")).strip()
            target = str(arguments.get("target", "")).strip()
            if not tool:
                return {
                    "status": "error",
                    "error": "Missing 'command'. Send {\"command\": \"<full command>\"}",
                }
            cmd_str = " ".join(x for x in (tool, args, target) if x)

        cmd_str = str(cmd_str).strip()
        if not cmd_str:
            return {"status": "error", "error": "empty command"}

        # 1. Deny list
        denied, dpat = _is_denied(cmd_str)
        if denied:
            return {
                "status": "denied",
                "command": cmd_str[:300],
                "reason": f"deny_list matched: {dpat}",
            }

        # 2. Destructive → ask user
        dest, xpat = _is_destructive(cmd_str)
        if dest:
            if self._bus is not None:
                try:
                    self._bus.emit("ASK_USER", {
                        "question": f"Run destructive command? {cmd_str[:200]}",
                        "reason": xpat,
                    })
                except Exception:
                    pass
            if self._ask is None:
                return {
                    "status": "blocked",
                    "reason": f"destructive (no ask handler): {xpat}",
                }
            allowed = self._ask(
                f"Destructive command detected:\n  {cmd_str[:300]}\nPattern: {xpat}"
            )
            if not allowed:
                return {"status": "blocked", "reason": "user denied"}

        # 3. Run via shell=True (pipes allowed)
        t0 = time.time()
        proc = None
        try:
            proc = subprocess.Popen(
                cmd_str,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                stdout_b, stderr_b = proc.communicate(timeout=_TIMEOUT)
                rc = proc.returncode
            except subprocess.TimeoutExpired:
                # Kill the entire process group — parent + all children.
                try:
                    os.killpg(os.getpgid(proc.pid), 9)  # SIGKILL
                except ProcessLookupError:
                    pass
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                return {
                    "status": "error",
                    "command": cmd_str[:300],
                    "error": f"timeout {_TIMEOUT}s (process group killed)",
                }

            # Decode with errors="replace" — no UTF-8 crashes.
            stdout_s = (stdout_b or b"").decode("utf-8", errors="replace")
            stderr_s = (stderr_b or b"").decode("utf-8", errors="replace")
            out = stdout_s + stderr_s

        except Exception as e:
            return {
                "status": "error",
                "command": cmd_str[:300],
                "error": str(e)[:200],
            }

        elapsed = time.time() - t0
        return {
            "status": "ok" if rc == 0 else "error",
            "command": cmd_str[:300],
            "returncode": rc,
            "elapsed_s": round(elapsed, 2),
            "output": _compress(out),
        }
