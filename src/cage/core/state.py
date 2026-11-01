from __future__ import annotations
import json
from pathlib import Path

class EngagementState:
    def __init__(self, workspace_dir: Path):
        self.filepath = workspace_dir / "state.json"
        self.data = self._load()
        # Force file to exist on Turn 1
        self.save()

    def _load(self) -> dict:
        if self.filepath.exists():
            try:
                with self.filepath.open("r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "known_endpoints": {},
            "discovered_parameters": [],
            "confirmed_findings": [],
            "active_session": False
        }

    def save(self):
        try:
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            with self.filepath.open("w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            print(f"Failed to save state.json: {e}")

    def update_from_llm(self, update_dict: dict):
        if not isinstance(update_dict, dict):
            return
        for ep, status in update_dict.get("endpoints", {}).items():
            self.data["known_endpoints"][ep] = status
        for p in update_dict.get("parameters", []):
            if p not in self.data["discovered_parameters"]:
                self.data["discovered_parameters"].append(p)
        self.save()

    def record_finding(self, vuln_class: str, severity: str, endpoint: str, parameter: str = "", payload: str = ""):
        """Called by orchestrator when emit_report succeeds."""
        # Avoid duplicates by endpoint + vuln_class
        for f in self.data["confirmed_findings"]:
            if f["endpoint"] == endpoint and f["vuln_class"] == vuln_class:
                return
        
        self.data["confirmed_findings"].append({
            "vuln_class": vuln_class,
            "severity": severity,
            "endpoint": endpoint,
            "parameter": parameter,
            "payload": payload[:200],  # Cap at 200 chars to prevent bloat
        })
        self.save()

    def get_prompt_context(self) -> str:
        lines = ["=== WHITEBOARD (STATE) ==="]
        
        if self.data["known_endpoints"]:
            lines.append("Known Endpoints:")
            for ep, status in self.data["known_endpoints"].items():
                lines.append(f"  - {ep} -> {status}")
        
        if self.data["discovered_parameters"]:
            lines.append(f"Known Parameters: {', '.join(self.data['discovered_parameters'])}")
        
        if self.data["confirmed_findings"]:
            lines.append("\nCONFIRMED FINDINGS (DO NOT re-test these):")
            for f in self.data["confirmed_findings"]:
                param_str = f" param={f['parameter']}" if f.get("parameter") else ""
                payload_str = f" payload={f['payload']}" if f.get("payload") else ""
                lines.append(f"  - [{f['severity']}] {f['vuln_class']} @ {f['endpoint']}{param_str}{payload_str}")
        
        if len(lines) == 1:
            return "=== WHITEBOARD (STATE) ===\nNo state recorded yet.\n"
        
        lines.append("==========================\n")
        return "\n".join(lines)
