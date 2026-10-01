"""The loader bridge -- the path that actually executes.

NightRelay used to be a pure relay: it could find an engine that exposed a script
port and forward to it. Almost no executor does that. What working executors
*do* offer is an autoexec folder and a Lua environment with HTTP. So the bridge
meets them there.

The mechanism, which is the one VSExecutor and friends use:

  1. NightRelay hosts a tiny loopback HTTP server (this module).
  2. A small Lua loader is pasted into the executor's autoexec folder.
  3. The loader registers, then polls for work, runs whatever it receives inside
     the live Roblox client, captures the printed output, and reports back.

Nothing here injects, hooks or bypasses anything -- the user's own executor is
the thing running the code. The bridge only carries the script across a loopback
socket and carries the result back.

Loopback only. There is no auth because there is no network exposure: the server
binds ``127.0.0.1`` and never a routable interface.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_PORT = 8792

# A loader that has not checked in for this long is treated as gone. The loader
# heartbeats every few seconds, so this is generous enough to survive a hitch
# without leaving a dead session pretending to be a live engine.
SESSION_TIMEOUT = 25.0

# How long /execute waits for a loader to report a result before giving up.
DEFAULT_WAIT = 20.0
MAX_SCRIPT_BYTES = 8 * 1024 * 1024  # mirrors the loader-side ceiling


@dataclass
class Session:
    """One connected loader -- one live Roblox client it is running inside."""

    id: str
    key: str = ""
    game: str = ""
    place: str = ""
    player: str = ""
    pid: int = 0
    protocol: str = "http"
    last_seen: float = field(default_factory=time.time)

    def alive(self, now: float | None = None) -> bool:
        return (now or time.time()) - self.last_seen < SESSION_TIMEOUT

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "game": self.game,
            "place": self.place,
            "player": self.player,
            "pid": self.pid,
            "protocol": self.protocol,
            "age_s": round(time.time() - self.last_seen, 1),
        }


@dataclass
class Job:
    """One queued script awaiting a loader."""

    id: str
    script: str
    session_id: str = ""
    created: float = field(default_factory=time.time)
    dispatched_to: str = ""
    done: bool = False
    ok: bool = False
    output: str = ""
    error: str = ""
    duration_ms: int = 0
    event: threading.Event = field(default_factory=threading.Event, repr=False)


class LoaderBridge:
    """Loopback server the Lua loader talks to. One per process."""

    def __init__(self, port: int = DEFAULT_PORT) -> None:
        self._port = int(port or DEFAULT_PORT)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []

    # -- lifecycle --------------------------------------------------------- #
    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def port(self) -> int:
        return self._port

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._port}" if self.running else ""

    def start(self, port: int | None = None) -> dict:
        with self._lock:
            if self._server is not None:
                return {"ok": True, "message": "loader bridge already running", **self.status()}
            if port:
                self._port = int(port)
            try:
                server = ThreadingHTTPServer(("127.0.0.1", self._port), _Handler)
            except OSError as exc:
                return {"ok": False, "message": f"port {self._port} unavailable: {exc}"}
            server.loader_bridge = self  # type: ignore[attr-defined]
            server.daemon_threads = True
            self._server = server
            self._thread = threading.Thread(
                target=server.serve_forever, name="nr-bridge", daemon=True
            )
            self._thread.start()
        return {
            "ok": True,
            "message": f"loader bridge listening on http://127.0.0.1:{self._port}",
            **self.status(),
        }

    def stop(self) -> dict:
        with self._lock:
            server = self._server
            self._server = None
            # release anyone still waiting on a result
            for job in self._jobs.values():
                if not job.done:
                    job.done = True
                    job.error = job.error or "bridge stopped"
                    job.event.set()
            if server is not None:
                threading.Thread(target=server.shutdown, daemon=True).start()
        return {"ok": True, "message": "loader bridge stopped"}

    # -- sessions ---------------------------------------------------------- #
    def register(self, payload: dict) -> dict:
        now = time.time()
        key = str(payload.get("session") or payload.get("id") or "").strip()
        with self._lock:
            self._expire(now)
            existing = next((s for s in self._sessions.values() if key and s.key == key), None)
            if existing is not None:
                session = existing
                session.last_seen = now
            else:
                sid = f"ldr-{uuid.uuid4().hex[:10]}"
                session = Session(id=sid, key=key or sid)
                self._sessions[sid] = session
            session.game = str(payload.get("game") or session.game or "")
            session.place = str(payload.get("place") or session.place or "")
            session.player = str(payload.get("player") or session.player or "")
            session.protocol = str(payload.get("protocol") or "http")
            try:
                session.pid = int(payload.get("pid") or session.pid or 0)
            except (TypeError, ValueError):
                pass
            return {
                "ok": True,
                "id": session.id,
                "poll_ms": 200,
                "heartbeat_ms": 5000,
                "session_timeout_s": int(SESSION_TIMEOUT),
            }

    def touch(self, session_id: str) -> dict:
        with self._lock:
            self._expire()
            session = self._sessions.get(session_id)
            if session is None:
                return {"ok": False, "message": "unknown session -- re-register"}
            session.last_seen = time.time()
            return {"ok": True, "pending": self._pending_for(session_id)}

    def poll(self, session_id: str) -> dict:
        """Hand this session any work waiting for it."""
        with self._lock:
            self._expire()
            session = self._sessions.get(session_id)
            if session is None:
                return {"ok": False, "jobs": [], "message": "unknown session"}
            session.last_seen = time.time()
            jobs = []
            for job in self._jobs.values():
                if job.done or job.dispatched_to:
                    continue
                if job.session_id and job.session_id != session_id:
                    continue
                job.dispatched_to = session_id
                jobs.append({"job_id": job.id, "script": job.script})
            return {"ok": True, "jobs": jobs}

    def report(self, payload: dict) -> dict:
        job = None
        with self._lock:
            session_id = str(payload.get("id") or "")
            self._expire()
            session = self._sessions.get(session_id)
            if session is not None:
                session.last_seen = time.time()
            job = self._jobs.get(str(payload.get("job_id") or ""))
            if job is None:
                return {"ok": False, "message": "unknown job"}
            job.done = True
            job.ok = bool(payload.get("ok"))
            job.output = str(payload.get("output") or "")[:65536]
            job.error = str(payload.get("error") or "")[:8192]
            try:
                job.duration_ms = int(payload.get("duration_ms") or 0)
            except (TypeError, ValueError):
                job.duration_ms = 0
        job.event.set()
        return {"ok": True}

    # -- execution --------------------------------------------------------- #
    def submit(self, script: str, session_id: str = "", wait: float = DEFAULT_WAIT) -> dict:
        """Queue a script and block until a loader reports back (or time out)."""
        if len(script.encode("utf-8")) > MAX_SCRIPT_BYTES:
            return {"ok": False, "executed": False, "error": "script exceeds the 8 MiB bridge limit"}

        with self._lock:
            self._expire()
            live = [s for s in self._sessions.values() if s.alive()]
            if not live:
                return {
                    "ok": False,
                    "executed": False,
                    "error": "no loader connected -- paste the NightRelay loader into your executor",
                }
            if session_id and session_id not in self._sessions:
                return {"ok": False, "executed": False, "error": f"session {session_id} is not connected"}
            job = Job(id=f"job-{uuid.uuid4().hex[:10]}", script=script, session_id=session_id)
            self._jobs[job.id] = job
            self._order.append(job.id)
            self._sweep()

        started = time.time()
        got = job.event.wait(max(0.1, wait))
        took = int((time.time() - started) * 1000)
        with self._lock:
            self._jobs.pop(job.id, None)
            if job.id in self._order:
                self._order.remove(job.id)

        if not got:
            return {
                "ok": False,
                "executed": False,
                "job_id": job.id,
                "error": f"no loader picked the job up within {wait:.0f}s",
                "duration_ms": took,
            }
        if not job.ok:
            return {
                "ok": False,
                "executed": True,
                "job_id": job.id,
                "output": job.output,
                "error": job.error or "the script raised an error",
                "duration_ms": job.duration_ms or took,
            }
        return {
            "ok": True,
            "executed": True,
            "job_id": job.id,
            "output": job.output,
            "error": "",
            "duration_ms": job.duration_ms or took,
        }

    # -- views ------------------------------------------------------------- #
    def sessions(self) -> list[dict]:
        with self._lock:
            self._expire()
            return [s.to_dict() for s in self._sessions.values() if s.alive()]

    def best_session(self) -> str:
        with self._lock:
            self._expire()
            live = [s for s in self._sessions.values() if s.alive()]
            if not live:
                return ""
            live.sort(key=lambda s: s.last_seen, reverse=True)
            return live[0].id

    def status(self) -> dict:
        live = self.sessions()
        return {
            "running": self.running,
            "url": self.url,
            "port": self._port if self.running else 0,
            "sessions": live,
            "connected": len(live),
        }

    # -- internals --------------------------------------------------------- #
    def _pending_for(self, session_id: str) -> int:
        return sum(
            1
            for job in self._jobs.values()
            if not job.done and not job.dispatched_to
            and (not job.session_id or job.session_id == session_id)
        )

    def _expire(self, now: float | None = None) -> None:
        now = now or time.time()
        dead = [sid for sid, s in self._sessions.items() if not s.alive(now)]
        for sid in dead:
            self._sessions.pop(sid, None)

    def _sweep(self) -> None:
        """Drop the oldest jobs once the queue grows past a sane ceiling."""
        while len(self._order) > 64:
            oldest = self._order.pop(0)
            job = self._jobs.pop(oldest, None)
            if job is not None and not job.done:
                job.done = True
                job.error = "dropped -- bridge queue overflow"
                job.event.set()


class _Handler(BaseHTTPRequestHandler):
    server_version = "NightRelayBridge/1.0"
    protocol_version = "HTTP/1.1"

    @property
    def bridge(self) -> LoaderBridge:
        return self.server.loader_bridge  # type: ignore[attr-defined,no-any-return]

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8", "replace") or "{}")
        except ValueError:
            data = {}
        return data if isinstance(data, dict) else {}

    def _route_get(self, path: str) -> bool:
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(path)
        query = parse_qs(parsed.query)
        route = parsed.path.rstrip("/") or "/"

        if route == "/health":
            self._send(200, {"ok": True, "bridge": "NightRelay", **self.bridge.status()})
            return True
        if route == "/poll":
            sid = (query.get("id") or [""])[0]
            self._send(200, self.bridge.poll(sid))
            return True
        if route == "/sessions":
            self._send(200, {"ok": True, "sessions": self.bridge.sessions()})
            return True
        return False

    def _route_post(self, path: str) -> bool:
        route = path.rstrip("/") or "/"
        body = self._body()
        if route == "/register":
            self._send(200, self.bridge.register(body))
            return True
        if route == "/heartbeat":
            self._send(200, self.bridge.touch(str(body.get("id") or "")))
            return True
        if route == "/report":
            self._send(200, self.bridge.report(body))
            return True
        if route == "/execute":
            script = body.get("script") or body.get("code") or ""
            wait = float(body.get("timeout") or DEFAULT_WAIT) / 1000.0 if body.get("timeout") else DEFAULT_WAIT
            result = self.bridge.submit(str(script), str(body.get("session") or ""), wait=wait)
            self._send(200 if result["ok"] else 502, result)
            return True
        return False

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self._route_get(self.path):
            self._send(404, {"ok": False, "message": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self._route_post(self.path):
            self._send(404, {"ok": False, "message": "not found"})

    def log_message(self, *args) -> None:  # silence the default stderr spam
        return


_bridge: LoaderBridge | None = None
_lock = threading.Lock()


def bridge() -> LoaderBridge:
    global _bridge
    if _bridge is None:
        with _lock:
            if _bridge is None:
                _bridge = LoaderBridge()
    return _bridge


def is_bridge_port(port: int) -> bool:
    """True when a port belongs to this process's own bridge."""
    b = _bridge
    return bool(b and b.running and b.port == port)
