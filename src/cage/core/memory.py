from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional


DDL = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    tool TEXT NOT NULL,
    args TEXT NOT NULL,
    result_summary TEXT NOT NULL,
    turn INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hypotheses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hyp_id TEXT UNIQUE NOT NULL,
    target TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    parameter TEXT,
    bug_class TEXT NOT NULL,
    evidence TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'OPEN',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT UNIQUE NOT NULL,
    vuln_class TEXT NOT NULL,
    severity TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    parameter TEXT,
    proof_request TEXT NOT NULL,
    proof_response TEXT NOT NULL,
    impact TEXT,
    remediation TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.utcnow().isoformat()


class ObservationLedger:
    def __init__(self, db_path: Path, workspace_dir: Path):
        self._db_path = db_path
        self._workspace = workspace_dir
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(DDL)
        self._conn.commit()
        self._memory_log = workspace_dir / "memory.log"

    # ── Observations ──────────────────────────────────────────────────────

    def record_observation(self, target: str, tool: str, args: str,
                           result_summary: str, turn: int = 0) -> None:
        self._conn.execute(
            "INSERT INTO observations (target, tool, args, result_summary, turn, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (target, tool, args[:500], result_summary[:1000], turn, _now()),
        )
        self._conn.commit()
        with self._memory_log.open("a", encoding="utf-8") as f:
            f.write(f"[T{turn}] tool={tool} args={args[:200]} → {result_summary[:200]}\n")

    def recent_memory(self, n: int = 20) -> list[dict]:
        cur = self._conn.execute(
            "SELECT tool, args, result_summary, turn FROM observations "
            "ORDER BY id DESC LIMIT ?", (n,)
        )
        return [dict(r) for r in cur.fetchall()]

    # ── Hypotheses ────────────────────────────────────────────────────────

    def add_hypothesis(self, hyp_id: str, target: str, endpoint: str,
                       bug_class: str, evidence: str,
                       parameter: Optional[str] = None) -> None:
        try:
            self._conn.execute(
                "INSERT INTO hypotheses (hyp_id, target, endpoint, parameter, bug_class, "
                "evidence, state, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (hyp_id, target, endpoint, parameter, bug_class, evidence, "OPEN", _now()),
            )
            self._conn.commit()
        except sqlite3.IntegrityError:
            pass

    def open_hypotheses(self, limit: int = 10) -> list[dict]:
        cur = self._conn.execute(
            "SELECT hyp_id, endpoint, parameter, bug_class, evidence FROM hypotheses "
            "WHERE state='OPEN' ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    # ── Findings ──────────────────────────────────────────────────────────

    def add_finding(self, finding_id: str, vuln_class: str, severity: str,
                    endpoint: str, proof_request: str, proof_response: str,
                    remediation: str, impact: str = "",
                    parameter: Optional[str] = None) -> None:
        try:
            self._conn.execute(
                "INSERT INTO findings (finding_id, vuln_class, severity, endpoint, parameter, "
                "proof_request, proof_response, impact, remediation, confirmed, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (finding_id, vuln_class, severity, endpoint, parameter,
                 proof_request, proof_response, impact, remediation, 1, _now()),
            )
            self._conn.commit()
        except sqlite3.IntegrityError:
            pass

    def confirmed_findings(self) -> list[dict]:
        cur = self._conn.execute("SELECT * FROM findings ORDER BY id")
        return [dict(r) for r in cur.fetchall()]

    # ── Summary ───────────────────────────────────────────────────────────

    def summary(self) -> dict:
        cur = self._conn.execute("SELECT COUNT(*) AS n FROM hypotheses WHERE state='OPEN'")
        open_h = cur.fetchone()["n"]
        return {
            "open_hypotheses": open_h,
            "confirmed_findings": len(self.confirmed_findings()),
            "recent_actions": self.recent_memory(10),
            "top_hypotheses": self.open_hypotheses(3),
        }

    def close(self) -> None:
        self._conn.close()