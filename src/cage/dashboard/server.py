from __future__ import annotations

import asyncio
import json
import queue
import threading
from collections import deque
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn


_STATIC = Path(__file__).parent / "static"
HISTORY_SIZE = 1000


class EventBus:
    def __init__(self) -> None:
        self._clients: set = set()
        self._thread_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._history: deque = deque(maxlen=HISTORY_SIZE)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._started = threading.Event()
        self.workspace: Optional[Path] = None   # set by orchestrator

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._started.set()

    def set_workspace(self, ws: Path) -> None:
        """Called by cli/main.py to know where logs live."""
        self.workspace = Path(ws)

    def emit(self, event_type: str, payload: dict) -> None:
        msg = {"type": event_type, "payload": payload}
        try:
            self._thread_queue.put_nowait(msg)
        except queue.Full:
            pass

    def get_history(self) -> list[dict]:
        return list(self._history)

    async def broadcast_loop(self) -> None:
        import time as _t
        while True:
            try:
                msg = self._thread_queue.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.05)
                continue

            msg["ts"] = _t.time()
            self._history.append(msg)

            if self._clients:
                text = json.dumps(msg, default=str)
                dead = []
                for ws in list(self._clients):
                    try:
                        await ws.send_text(text)
                    except Exception:
                        dead.append(ws)
                for d in dead:
                    self._clients.discard(d)


def build_app(bus: EventBus) -> FastAPI:
    app = FastAPI()

    @app.get("/")
    async def root():
        html = (_STATIC / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(html)

    @app.get("/api/log/{name}")
    async def get_log(name: str):
        """Return the last N lines of a log file. Names: agent_actions, cage."""
        if bus.workspace is None:
            return JSONResponse({"error": "workspace not set"}, status_code=500)

        if name == "agent_actions":
            path = bus.workspace / "agent_actions.log"
        elif name == "cage":
            path = bus.workspace / "cage.log"
        else:
            return JSONResponse({"error": f"unknown log '{name}'"}, status_code=404)

        if not path.exists():
            return JSONResponse({"lines": [], "path": str(path), "exists": False})

        try:
            # Read last 2000 lines
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            tail = lines[-2000:]
            return JSONResponse({
                "lines": tail,
                "total": len(lines),
                "path": str(path),
                "exists": True,
            })
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        await ws.accept()
        bus._clients.add(ws)

        for msg in bus.get_history():
            try:
                await ws.send_text(json.dumps(msg, default=str))
            except Exception:
                break
        try:
            await ws.send_text(json.dumps({"type": "_HISTORY_DONE", "payload": {}}))
        except Exception:
            pass

        try:
            while True:
                await ws.receive_text()
        except Exception:
            pass
        finally:
            bus._clients.discard(ws)

    @app.on_event("startup")
    async def _startup():
        bus.set_loop(asyncio.get_running_loop())
        asyncio.create_task(bus.broadcast_loop())

    return app


def start_dashboard(host: str = "127.0.0.1", port: int = 7777) -> EventBus:
    import socket
    try:
        socket.getaddrinfo(host, port)
    except OSError:
        print(f"[Dashboard] Cannot resolve '{host}' — using 127.0.0.1")
        host = "127.0.0.1"

    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError
    except (ValueError, TypeError):
        port = 7777

    bus = EventBus()
    app = build_app(bus)

    def _run():
        try:
            uvicorn.run(app, host=host, port=port, log_level="warning")
        except Exception as e:
            print(f"[Dashboard] FAILED: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    bus._started.wait(timeout=5.0)
    print(f"[Dashboard] Live at http://{host}:{port}")
    return bus
