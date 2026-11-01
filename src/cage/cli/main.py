"""
main.py — CAGE CLI.
"""

from __future__ import annotations

import logging
import re
import sys
import time
from pathlib import Path

import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

# Resolve project root based on this file's location (src/cage/cli/main.py)
_PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Load secrets
_SECRETS = _PROJECT_ROOT / "secrets" / ".env"
if _SECRETS.exists():
    load_dotenv(_SECRETS)
else:
    load_dotenv()

from cage.core.budget import BudgetTracker
from cage.core.context import ContextBuilder
from cage.core.memory import ObservationLedger
from cage.core.orchestrator import Orchestrator
from cage.reasoning_engine import get_llm
from cage.tools.registry import ToolRegistry


console = Console()

BANNER = """
[bold cyan]
 ██████╗ █████╗  ██████╗ ███████╗
██╔════╝██╔══██╗██╔════╝ ██╔════╝
██║     ███████║██║  ███╗█████╗  
██║     ██╔══██║██║   ██║██╔══╝  
╚██████╗██║  ██║╚██████╔╝███████╗
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
[/bold cyan]
[bold white]CAGE — Controlled Autonomous Generation Engine[/bold white]
[bold green]Author: Tufail Athar[/bold green]
"""


def _load_cfg() -> dict:
    p = _PROJECT_ROOT / "config" / "default.yaml"
    if p.exists():
        return yaml.safe_load(p.read_text()) or {}
    return {}


def _sanitize(s: str) -> str:
    out = "".join(c if c.isalnum() or c in "-_." else "_" for c in s)
    return out.strip("_.")[:80] or "target"


def _ask_terminal(question: str) -> bool:
    try:
        ans = input(f"\n[CAGE] {question} (y/N): ").strip().lower()
        return ans in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _setup_log(ws: Path) -> logging.Logger:
    logger = logging.getLogger("cage")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fh = logging.FileHandler(ws / "cage.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.CRITICAL)
    logger.addHandler(ch)
    return logger


def _default_remediation(vuln_class: str) -> str:
    vc = (vuln_class or "").lower()
    if "sql" in vc:
        return (
            "• Use parameterized queries / prepared statements (never concatenate user input into SQL).\n"
            "• Apply input validation and enforce least-privilege DB accounts.\n"
            "• Reject or escape unexpected characters at the application layer.\n"
            "• Deploy a WAF as a defense-in-depth measure (not a primary control)."
        )
    if "xss" in vc or "cross-site" in vc:
        return (
            "• Context-aware output encoding (HTML, JS, URL, CSS) on every reflected value.\n"
            "• Apply Content Security Policy (CSP) headers to limit script execution.\n"
            "• Use HTML sanitization libraries for user-authored rich content.\n"
            "• Set HttpOnly and SameSite flags on session cookies."
        )
    if "access control" in vc or "idor" in vc or "authorization" in vc:
        return (
            "• Enforce authentication and authorization on every endpoint (server-side).\n"
            "• Deny by default — explicitly allow only authorized roles.\n"
            "• Do not rely on hidden URLs or predictable identifiers as access control.\n"
            "• Log access-control failures and monitor for enumeration attempts."
        )
    if "ssrf" in vc:
        return (
            "• Whitelist outbound destinations (host + port) at the application layer.\n"
            "• Block private IP ranges (RFC1918), localhost, and 169.254.169.254 / cloud metadata.\n"
            "• Do not follow redirects without re-validating the destination.\n"
            "• Require authentication for server-side URL fetchers."
        )
    if "csrf" in vc:
        return (
            "• Issue per-session CSRF tokens on every state-changing request.\n"
            "• Use SameSite=Lax or SameSite=Strict cookie attribute.\n"
            "• Require re-authentication for sensitive actions.\n"
            "• Validate Origin / Referer headers as a secondary check."
        )
    if "command injection" in vc or "rce" in vc:
        return (
            "• Avoid invoking shell interpreters with user input.\n"
            "• Use library APIs instead of shell commands where possible.\n"
            "• If shell is necessary, allowlist arguments and never pass raw input.\n"
            "• Run processes under a low-privilege user."
        )
    if "path traversal" in vc or "lfi" in vc:
        return (
            "• Never pass user-supplied paths to file APIs.\n"
            "• Use an allowlist of permitted files / chroot / jail directories.\n"
            "• Reject input containing '..' and absolute paths.\n"
            "• Resolve the final path and verify it stays within the allowed root."
        )
    if "information disclosure" in vc or "exposure" in vc:
        return (
            "• Remove debug output, stack traces, and verbose errors from production.\n"
            "• Do not expose internal identifiers, config, or secrets in responses.\n"
            "• Review error handling to return generic messages to clients.\n"
            "• Restrict access to sensitive endpoints and files."
        )
    return (
        "• Review the affected endpoint and apply the principle of least privilege.\n"
        "• Validate and sanitize all user-supplied input on the server side.\n"
        "• Follow OWASP guidelines for the identified vulnerability class.\n"
        "• Retest after applying the fix."
    )


def _extract_payload(finding: dict) -> str:
    explicit = (finding.get("payload") or "").strip()
    if explicit:
        return explicit

    req = (finding.get("proof_request") or "").strip()
    param = (finding.get("parameter") or "").strip()

    if req:
        cookie_match = re.search(r'(?i)Cookie:\s*([^\n]+)', req)
        if cookie_match:
            cookies = cookie_match.group(1)
            for part in cookies.split(';'):
                part = part.strip()
                if '=' in part and 'session' not in part.lower():
                    return part

        if param:
            pattern = re.compile(
                r'(?i)(?:^|[?&;,\s])' + re.escape(param) + r'\s*=\s*([^\s;&,"\']+)'
            )
            m = pattern.search(req)
            if m:
                return f"{param}={m.group(1)}"

        url_match = re.search(r'[?&](\w+)=([^\s&"\']+)', req)
        if url_match:
            return f"{url_match.group(1)}={url_match.group(2)}"

    return param or "-"


def run() -> None:
    console.print(BANNER)
    console.print(Rule("[bold cyan]Session Setup[/bold cyan]"))

    # Wrap the entire interactive setup in a try/except to catch Ctrl+C
    try:
        # ── 1. Target ────────────────────────────────────────────────────────
        console.print("\n[bold]Step 1: Target URL[/bold]")
        console.print("[dim]Enter a single URL. No wildcard expansion.[/dim]")
        target = Prompt.ask("[green]Target[/green]").strip()
        if not target:
            console.print("[red]No target — exiting.[/red]")
            sys.exit(1)
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        # ── 2. Workspace ─────────────────────────────────────────────────────
        ws_name = _sanitize(target.replace("https://", "").replace("http://", ""))
        workspace = _PROJECT_ROOT / "workspaces" / ws_name
        workspace.mkdir(parents=True, exist_ok=True)
        console.print(f"[dim]Workspace: {workspace}[/dim]")

        # ── 3. Custom instructions ───────────────────────────────────────────
        console.print("\n[bold]Step 2: Custom Instructions (optional)[/bold]")
        console.print("[dim]Press Enter to skip. Examples: 'CTF: find flag', 'focus on /api'[/dim]")
        user_prompt = Prompt.ask("[yellow]Instructions[/yellow]", default="").strip()
        if user_prompt:
            (workspace / "user_prompt.txt").write_text(user_prompt, encoding="utf-8")
            console.print("[green]✓ Custom instructions applied.[/green]")
        else:
            up = workspace / "user_prompt.txt"
            if up.exists():
                up.unlink()

        # ── 4. Dashboard ─────────────────────────────────────────────────────
        console.print("\n[bold]Step 3: Dashboard[/bold]")
        dash_host = Prompt.ask("Dashboard host", default="127.0.0.1").strip()
        dash_port_str = Prompt.ask("Dashboard port", default="7777").strip()
        try:
            dash_port = int(dash_port_str)
        except ValueError:
            dash_port = 7777

    except KeyboardInterrupt:
        console.print("\n[bold red][-] Aborted.[/bold red] [dim]Session closed safely.[/dim]")
        sys.exit(0)
    except EOFError:
        console.print("\n[bold red][-] Aborted.[/bold red] [dim]Session closed safely.[/dim]")
        sys.exit(0)

    # ── 5. Dashboard Start (Outside the try block) ───────────────────────
    from cage.dashboard.server import start_dashboard
    bus = start_dashboard(host=dash_host, port=dash_port)
    bus.set_workspace(workspace)
    console.print(f"[green]✓ Dashboard: http://{dash_host}:{dash_port}[/green]")

    # ── 6. Model ────────────────────────────────────────────────────────
    console.print("\n[bold]Step 4: Model[/bold]")
    console.print("  Using [bold bright_cyan]Meta Muse Spark Open[/bold bright_cyan]")
    adapter = get_llm()

    # ── 7. Wire everything ──────────────────────────────────────────────
    console.print(Rule("[bold cyan]Initializing[/bold cyan]"))
    logger = _setup_log(workspace)

    cfg = _load_cfg()
    max_turns = int(cfg.get("engine", {}).get("max_turns", 80))

    ledger = ObservationLedger(workspace / "observations.db", workspace)
    budget = BudgetTracker(max_turns=max_turns)

    registry = ToolRegistry(
        ledger=ledger,
        workspace_dir=workspace,
        ask_cb=_ask_terminal,
        dashboard_bus=bus,
    )

    context = ContextBuilder(
        ledger=ledger,
        budget=budget,
        target=target,
        workspace_dir=workspace,
    )

    def _on_status(msg: str) -> None:
        pass

    orchestrator = Orchestrator(
        adapter=adapter,
        ledger=ledger,
        budget=budget,
        registry=registry,
        context=context,
        workspace_dir=workspace,
        target=target,
        logger=logger,
        dashboard_bus=bus,
        status_cb=_on_status,
    )

    # ── 8. Launch ────────────────────────────────────────────────────────
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Workspace:[/bold] {workspace}\n"
        f"[bold]Max Turns:[/bold] {max_turns}\n"
        f"[bold]Dashboard:[/bold] http://{dash_host}:{dash_port}",
        title="[cyan]Ready[/cyan]", border_style="cyan",
    ))

    try:
        if not Confirm.ask("\n[green]Launch engagement?[/green]", default=False):
            console.print("[yellow]Aborted.[/yellow]")
            sys.exit(0)
    except KeyboardInterrupt:
        console.print("\n[bold red][-] Aborted.[/bold red] [dim]Session closed safely.[/dim]")
        sys.exit(0)

    console.print()
    console.print(Rule("[bold red]ENGAGEMENT ACTIVE[/bold red]"))
    console.print()

    spinner = Spinner("dots", style="cyan")

    def _render_status() -> Text:
        row = Text()
        row.append_text(spinner.render(time.time()))
        row.append(" ")
        row.append("Running", style="bold green")
        return row

    start = time.time()

    findings = []
    done_flag = {"done": False}

    try:
        with Live(_render_status(), console=console, refresh_per_second=10, transient=False) as live:
            import threading

            def _refresh_loop():
                while not done_flag["done"]:
                    try:
                        live.update(_render_status())
                    except Exception:
                        break
                    time.sleep(0.08)

            refresh_thread = threading.Thread(target=_refresh_loop, daemon=True)
            refresh_thread.start()

            try:
                findings = orchestrator.run()
            except KeyboardInterrupt:
                done_flag["done"] = True
                live.stop()
                console.print("\n[bold red][-] Aborted.[/bold red] [dim]Session closed safely.[/dim]")
                ledger.close()
                sys.exit(0)
            finally:
                done_flag["done"] = True

    except Exception as e:
        done_flag["done"] = True
        console.print(f"[red]Engagement failed: {e}[/red]")
        findings = ledger.confirmed_findings()

    elapsed = (time.time() - start) / 60

    # ── 9. Results ───────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[cyan]Engagement Complete[/cyan]"))
    console.print(Panel(
        f"[bold]Duration:[/bold] {elapsed:.1f} min\n"
        f"[bold]Turns:[/bold] {budget.current_turn}\n"
        f"[bold]Tokens:[/bold] {budget.tokens_used}\n"
        f"[bold]Findings:[/bold] {len(findings)}",
        title="Budget Summary",
    ))

    if findings:
        table = Table(title=f"Findings ({len(findings)})", header_style="bold red")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Type")
        table.add_column("Endpoint")
        table.add_column("Parameter", no_wrap=True)
        table.add_column("Payload Used", style="yellow")
        for f in findings:
            payload = _extract_payload(f)
            table.add_row(
                f["severity"],
                f["vuln_class"],
                f["endpoint"][:60],
                f.get("parameter") or "-",
                payload[:80] if payload else "-",
            )
        console.print(table)

        console.print("\n[bold cyan]Summary[/bold cyan]")
        summary_lines = []
        summary_lines.append(
            f"Engagement ran for [bold]{budget.current_turn}[/bold] turns "
            f"across [bold]{elapsed:.1f}[/bold] minutes and "
            f"identified [bold red]{len(findings)}[/bold red] confirmed "
            f"vulnerabilit{'y' if len(findings)==1 else 'ies'}."
        )
        sev_counts = {}
        for f in findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        sev_color = {"CRITICAL":"red","HIGH":"orange3","MEDIUM":"yellow",
                     "LOW":"blue","INFO":"dim"}
        sev_str = ", ".join(
            f"[{sev_color.get(s,'white')}]{n}× {s}[/]"
            for s, n in sorted(sev_counts.items(), key=lambda x: -x[1])
        )
        summary_lines.append(f"Severity breakdown: {sev_str}")
        summary_lines.append("")
        summary_lines.append("[bold]Findings:[/bold]")
        for f in findings:
            payload = _extract_payload(f)
            summary_lines.append(
                f"  • [{f['severity']}] {f['vuln_class']} — "
                f"[dim]{f['endpoint'][:80]}[/dim]"
            )
            if payload and payload != "-":
                summary_lines.append(
                    f"    [yellow]Payload:[/yellow] [bold]{payload}[/bold]"
                )
        console.print(Panel(
            "\n".join(summary_lines),
            title="[bold cyan]What Happened[/bold cyan]",
            border_style="cyan",
        ))

        console.print("\n[bold green]Remediation[/bold green]")
        for f in findings:
            remediation_text = f.get("remediation") or _default_remediation(f["vuln_class"])
            impact_text = f.get("impact") or ""
            payload = _extract_payload(f)

            body = ""
            if payload and payload != "-":
                body += f"[bold yellow]Payload Used:[/bold yellow] [bold]{payload}[/bold]\n\n"
            if impact_text:
                body += f"[bold]Impact:[/bold] {impact_text}\n\n"
            body += f"[bold]How to fix:[/bold]\n{remediation_text}"

            console.print(Panel(
                body,
                title=f"[{f['severity']}] {f['vuln_class']}",
                border_style="green",
            ))

        console.print(f"\n[green]Full report:[/green] {workspace / 'findings.md'}")
        console.print(f"[green]Summary:[/green]     {workspace / 'summary.md'}")
        console.print(f"[green]CAGE log:[/green]    {workspace / 'cage.log'}")
    else:
        console.print("[yellow]No confirmed findings.[/yellow]")
        console.print(f"\n[green]CAGE log:[/green] {workspace / 'cage.log'}")

    ledger.close()


if __name__ == "__main__":
    run()
