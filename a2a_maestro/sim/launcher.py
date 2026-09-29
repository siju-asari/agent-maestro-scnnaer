"""Launch/stop the local mock A2A agent servers."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .agents import MOCK_AGENT_CARDS

_WELL_KNOWN_PATHS = {"/.well-known/agent-card.json", "/.well-known/agent.json"}


def _make_handler(card: dict) -> type[BaseHTTPRequestHandler]:
    body = json.dumps(card).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (stdlib API)
            if self.path in _WELL_KNOWN_PATHS:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, fmt: str, *args) -> None:  # silence per-request logging
            return

    return Handler


@dataclass
class RunningAgent:
    name: str
    url: str
    port: int
    server: ThreadingHTTPServer
    thread: threading.Thread


def start_all(host: str = "127.0.0.1") -> list[RunningAgent]:
    """Start every mock agent on its assigned port. Returns handles to stop them."""
    running: list[RunningAgent] = []
    for port, card in MOCK_AGENT_CARDS.items():
        handler_cls = _make_handler(card)
        server = ThreadingHTTPServer((host, port), handler_cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        running.append(
            RunningAgent(
                name=card["name"],
                url=f"http://{host}:{port}",
                port=port,
                server=server,
                thread=thread,
            )
        )
    return running


def stop_all(running: list[RunningAgent]) -> None:
    for agent in running:
        agent.server.shutdown()
        agent.server.server_close()
