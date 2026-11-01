from __future__ import annotations

import uuid
from pathlib import Path

from cage.tools.base import BaseTool


class EmitReportTool(BaseTool):
    # Added dashboard_bus to the constructor
    def __init__(self, ledger, workspace_dir: Path, dashboard_bus=None):
        self._ledger = ledger
        self._ws = workspace_dir
        self._bus = dashboard_bus

    @property
    def name(self) -> str:
        return "emit_report"

    def execute(self, arguments: dict) -> dict:
        for k in ("vuln_class", "severity", "endpoint", "proof_request",
                  "proof_response", "remediation"):
            if not arguments.get(k):
                return {"status": "error", "error": f"missing {k}"}

        # ── P3 FIX: THE BOUNCER ──────────────────────────────────────
        impact = arguments.get("impact", "").lower()
        payload = arguments.get("proof_request", "").lower()
        
        bad_phrases = ["informational", "no vulnerability confirmed", "no action required", "none demonstrated"]
        if any(phrase in impact for phrase in bad_phrases) or len(impact) < 40:
            return {"status": "rejected", "reason": "Impact too short or describes an informational observation, not a vulnerability."}
            
        if payload in ["n/a", "none", "unauthenticated get", ""]:
            return {"status": "rejected", "reason": "Payload is empty or N/A. Real findings require a specific exploit payload."}
        # ─────────────────────────────────────────────────────────────

        fid = str(uuid.uuid4())
        self._ledger.add_finding(
            finding_id=fid,
            vuln_class=arguments["vuln_class"],
            severity=arguments["severity"],
            endpoint=arguments["endpoint"],
            parameter=arguments.get("parameter"),
            proof_request=arguments["proof_request"],
            proof_response=arguments["proof_response"],
            impact=arguments.get("impact", ""),
            remediation=arguments["remediation"],
        )
        self._write_md(fid, arguments)

        # ── P3 LIVE BROADCAST: Tell the dashboard immediately ────────
        if self._bus is not None:
            try:
                self._bus.emit("FINDING", {
                    "finding_id": fid,
                    "vuln_class": arguments["vuln_class"],
                    "severity": arguments["severity"],
                    "endpoint": arguments["endpoint"],
                    "parameter": arguments.get("parameter"),
                    "impact": arguments.get("impact", ""),
                })
            except Exception:
                pass
        # ─────────────────────────────────────────────────────────────

        return {"status": "ok", "finding_id": fid}

    def _write_md(self, fid: str, args: dict) -> None:
        p = self._ws / "findings.md"
        with p.open("a", encoding="utf-8") as f:
            f.write(f"\n## [{args['severity']}] {args['vuln_class']}\n")
            f.write(f"**ID:** `{fid}`\n")
            f.write(f"**Target:** `{args['endpoint']}`\n")
            if args.get("parameter"):
                f.write(f"**Parameter:** `{args['parameter']}`\n")
            if args.get("impact"):
                f.write(f"**Impact:** {args['impact']}\n")
            f.write(f"\n**Proof Request:**\n```\n{args['proof_request'][:1500]}\n```\n")
            f.write(f"\n**Proof Response:**\n```\n{args['proof_response'][:800]}\n```\n")
            f.write(f"\n**Remediation:** {args['remediation']}\n\n---\n")


class FinishEngagementTool(BaseTool):
    @property
    def name(self) -> str:
        return "finish_engagement"

    def execute(self, arguments: dict) -> dict:
        return {"status": "complete", "reason": arguments.get("reason", "done")}
