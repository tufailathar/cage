# CAGE Source Code

This directory contains the core Python source code for CAGE.

The project uses the standard Python `src` layout. The importable package is contained within the `cage/` directory.

## Architecture

CAGE uses a five-layer architecture to separate LLM reasoning from controlled execution. Meta Muse Spark Open guides strategic decisions, while the Python engine manages execution, state, safety checks, and validation.

| Layer | Location | Responsibility |
|---|---|---|
| **CLI** | `cage/cli/main.py` | Interactive setup, Rich terminal UI, live dashboard launcher, and final report generation. |
| **Reasoning** | `cage/reasoning_engine.py` | Integrates Meta Muse Spark Open via Baseten, handles API communication, and validates structured JSON responses. |
| **Orchestrator** | `cage/core/orchestrator.py` | Coordinates the agent's execution loop, state updates, stall detection, finish gates, and tool dispatch. |
| **Tools** | `cage/tools/` | Executes actions and validates results. |
| **Memory** | `cage/core/state.py`, `cage/core/memory.py` | Maintains a persistent JSON whiteboard (`state.json`) for testing progress and a SQLite ledger for recording observations. |

### Tools

- `kali_tool.py`: Shell command execution with tokenization, deny-list checks, and execution timeouts.
- `browser_tool.py`: Headless Chromium fallback (`browser_fetch`) for JavaScript-rendered pages and requests that standard `curl` cannot handle.
- `report_tools.py`: Bouncer validation logic to filter potential false positives before reporting findings.


For installation, configuration, and usage instructions, see the [main README](../README.md).