"""A deliberately inert stand-in engine, for proving the relay path works.

This is **not** an executor and it is not a step towards one. It accepts a script
over the same local HTTP contract a real engine would, records what arrived, and
acknowledges it. Nothing is compiled, nothing is injected, nothing runs inside
Roblox.

Its only job is to separate two questions that are otherwise impossible to tell
apart when a script fails to run:

  1. Does NightRelay's side work -- discovery, attach, relay, result recording?
  2. Is there an engine on the other end to execute?

With the self-test engine started, a run that reports success proves (1) and
leaves (2) as the only open item. Every response carries a marker header so
discovery and the UI can label it unmistakably as a self-test rather than let it
pass for a real engine.

It also stops itself, so it cannot be left running by accident.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SELFTEST_HEADER = "X-NightRelay-SelfTest"
SELFTEST_PORT = 8799
DEFAULT_TTL = 180.0
MAX_RECORDED = 20


class _Handler(BaseHTTPRequestHandler):
    server_version = "NightRelaySelfTest/1.0"
    protocol_version = "HTTP/1.1"

    def _respond(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(SELFTEST_HEADER, "1")
        self.end_headers()
        self.wfile.write(body)

    def _record(self, script: str) -> None:
        state = self.server.selftest_state  # type: ignore[attr-defined]
        with state["lock"]:
            state["received"].insert(
                0,
                {
                    "time": time.strftime("%H:%M:%S"),
                    "bytes": len(script.encode("utf-8")),
                    "preview": script.strip().splitlines()[0][:100] if script.strip() else "",
                },
            )
            del state["received"][MAX_RECORDED:]

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8", "replace") or "{}")
        except ValueError:
            payload = {}
        script = ""
        if isinstance(payload, dict):
            for key in ("script", "code", "source", "lua"):
                if isinstance(payload.get(key), str):
                    script = payload[key]
                    break
        self._record(script)
        self._respond(
            200,
            {
                "ok": True,
                "self_test": True,
                "executed": False,
                "received_bytes": len(script.encode("utf-8")),
                "note": (
                    "NightRelay self-test engine: the script arrived intact and was "
                    "recorded. It was NOT run -- this stub has no Lua engine."
                ),
            },
        )

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        state = self.server.selftest_state  # type: ignore[attr-defined]
        with state["lock"]:
            received = list(state["received"])
        self._respond(200, {"ok": True, "self_test": True, "received": received})

    def log_message(self, *args) -> None:  # silence the default stderr spam
        return


class SelfTestEngine:
    """Runs the stub on a loopback port with a self-imposed lifetime."""

    def __init__(self, port: int = SELFTEST_PORT, ttl: float = DEFAULT_TTL) -> None:
        self.port = port
        self.ttl = ttl
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._timer: threading.Timer | None = None
        self._started = 0.0
        self._lock = threading.Lock()
        self._state = {"received": [], "lock": threading.Lock()}

    @property
    def running(self) -> bool:
        return self._server is not None

    def start(self, port: int | None = None) -> dict:
        with self._lock:
            if self._server is not None:
                return {"ok": True, "message": "self-test engine is already running",
                        **self.status()}
            if port:
                self.port = port
            try:
                server = ThreadingHTTPServer(("127.0.0.1", self.port), _Handler)
            except OSError as exc:
                return {"ok": False, "message": f"port {self.port} unavailable: {exc}"}
            server.selftest_state = self._state  # type: ignore[attr-defined]
            server.daemon_threads = True
            self._server = server
            self._started = time.time()
            self._thread = threading.Thread(
                target=server.serve_forever, name="nr-selftest", daemon=True
            )
            self._thread.start()
            if self.ttl:
                self._timer = threading.Timer(self.ttl, self.stop)
                self._timer.daemon = True
                self._timer.start()
        return {
            "ok": True,
            "message": (
                f"self-test engine listening on http://127.0.0.1:{self.port}/execute "
                f"for {int(self.ttl)}s"
            ),
            "url": f"http://127.0.0.1:{self.port}/execute",
            "ttl": self.ttl,
        }

    def stop(self) -> dict:
        with self._lock:
            server = self._server
            self._server = None
            if self._timer:
                self._timer.cancel()
                self._timer = None
            if server is not None:
                threading.Thread(target=server.shutdown, daemon=True).start()
        return {"ok": True, "message": "self-test engine stopped"}

    def status(self) -> dict:
        with self._state["lock"]:
            received = list(self._state["received"])
        elapsed = time.time() - self._started if self._started else 0.0
        return {
            "running": self.running,
            "url": f"http://127.0.0.1:{self.port}/execute" if self.running else "",
            "port": self.port if self.running else 0,
            "uptime_s": int(elapsed),
            "remaining_s": max(0, int(self.ttl - elapsed)) if self.running else 0,
            "received": received,
        }


_engine: SelfTestEngine | None = None
_lock = threading.Lock()


def engine() -> SelfTestEngine:
    global _engine
    if _engine is None:
        with _lock:
            if _engine is None:
                _engine = SelfTestEngine()
    return _engine


def is_selftest_url(url: str) -> bool:
    """True when a candidate URL points at this stub rather than a real engine."""
    eng = _engine
    if eng is None or not eng.running or not url:
        return False
    return url.startswith(f"http://127.0.0.1:{eng.port}/")
