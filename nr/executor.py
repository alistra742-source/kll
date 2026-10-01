"""Execution backends.

NightRelay is a *relay*: it owns the console, the attach lifecycle and the
pipeline, and pushes Lua to whichever execution backend is present.

Two backends ship:

``dll``
    A standard remote-thread ``LoadLibraryW`` injector. Point it at a module you
    are licensed to use; it allocates the path in the target, spawns the thread,
    then scrubs and frees the remote buffer so no readable copy of the path is
    left behind.

``external``
    Talks to an executor that is already installed and exposing a local bridge
    (HTTP endpoint or named pipe). NightRelay probes the usual ports and
    forwards the script verbatim.

Neither backend contains or ships a bypass. Modern Roblox clients are protected
by a kernel-level anti-tamper layer; loading anything into them is a fight
NightRelay does not pretend to win on your behalf.
"""

from __future__ import annotations

import ctypes
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config, roblox

# Names of common executor bridges worth probing.
COMMON_PORTS = (6969, 5500, 5555, 3000, 4000, 8080, 7957, 25565, 3058, 13583, 3012)
PROBE_PATHS = ("/execute", "/api/execute", "/exec", "/run", "/api/run")


@dataclass
class Result:
    ok: bool
    backend: str
    message: str
    detail: str = ""
    duration_ms: int = 0
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "backend": self.backend,
            "message": self.message,
            "detail": self.detail,
            "duration_ms": self.duration_ms,
            **self.extra,
        }


# Rights an injector needs, versus rights a read-only probe needs.
INJECT_RIGHTS = (
    roblox.PROCESS_CREATE_THREAD
    | roblox.PROCESS_VM_OPERATION
    | roblox.PROCESS_VM_WRITE
    | roblox.PROCESS_VM_READ
)
PROBE_RIGHTS = roblox.PROCESS_QUERY_LIMITED_INFORMATION | roblox.PROCESS_VM_READ


# --------------------------------------------------------------------------- #
# DLL injector
# --------------------------------------------------------------------------- #
class Injector:
    """Remote-thread LoadLibraryW injector with post-injection scrubbing."""

    def __init__(self) -> None:
        self._attached: dict[int, int] = {}
        self._can_inject: dict[int, bool] = {}
        self._load_library: int = 0
        self._lock = threading.Lock()

    # -- helpers ---------------------------------------------------------- #
    def _resolve_load_library(self) -> int:
        if self._load_library:
            return self._load_library
        # roblox.kernel32 already declares restypes/argtypes. Using
        # ctypes.windll.kernel32 here left them at the ctypes defaults, so the
        # 64-bit pointer VirtualAllocEx returns was truncated to 32 bits and the
        # very next WriteProcessMemory failed on a garbage address.
        kernel32 = roblox.kernel32
        handle = kernel32.GetModuleHandleW("kernel32.dll")
        addr = kernel32.GetProcAddress(ctypes.c_void_p(handle), b"LoadLibraryW")
        self._load_library = int(addr or 0)
        return self._load_library

    def attached_pids(self) -> list[int]:
        with self._lock:
            return sorted(self._attached)

    def is_attached(self, pid: int) -> bool:
        with self._lock:
            return pid in self._attached

    def _open(self, pid: int, rights: int) -> int:
        return int(roblox.kernel32.OpenProcess(rights, False, pid) or 0)

    def link(self, pid: int) -> Result:
        """Attach in the honest sense: hold a live handle on the client.

        This succeeds whenever the target is reachable, and it reports exactly
        how much access the client granted. On a protected client the read-only
        rights are granted and the injection rights are not -- that is the
        anti-tamper working, and it is surfaced as a fact rather than an error.
        """
        roblox.enable_debug_privilege()
        identity = roblox.identity()
        client = next((p for p in roblox.find_roblox(include_studio=False) if p.pid == pid), None)

        with self._lock:
            if pid in self._attached:
                return Result(
                    True,
                    "link",
                    f"attached to {identity.get('username') or 'the client'}",
                    f"pid {pid} was already linked",
                    extra={"pid": pid, "identity": identity, "can_inject": self._can_inject.get(pid, False)},
                )

        if not roblox.same_architecture(pid):
            return Result(
                False,
                "link",
                "architecture mismatch",
                "NightRelay is 64-bit and the client is not.",
                extra={"pid": pid, "identity": identity},
            )

        inject_handle = self._open(pid, INJECT_RIGHTS | roblox.PROCESS_QUERY_INFORMATION)
        can_inject = bool(inject_handle)
        probe_handle = inject_handle or self._open(pid, PROBE_RIGHTS)
        if not probe_handle:
            code = ctypes.get_last_error()
            hint = (
                "access denied — run NightRelay as administrator"
                if code == 5
                else f"OpenProcess failed (WinError {code})"
            )
            return Result(False, "link", "could not attach", hint, extra={"pid": pid, "identity": identity})

        with self._lock:
            self._attached[pid] = int(probe_handle)
            self._can_inject[pid] = can_inject

        who = identity.get("display_name") or identity.get("username") or "unknown account"
        detail = (
            f"memory write access granted — a module can be loaded"
            if can_inject
            else "read-only access: the client refuses remote memory writes (anti-tamper)"
        )
        return Result(
            True,
            "link",
            f"attached as {who}",
            detail,
            extra={
                "pid": pid,
                "identity": identity,
                "can_inject": can_inject,
                "title": client.title if client else "",
                "memory_mb": client.memory_mb if client else 0,
                "place": roblox.place_from_log(),
            },
        )

    def attach(self, pid: int) -> Result:
        return self.link(pid)

    def detach(self, pid: int) -> Result:
        with self._lock:
            handle = self._attached.pop(pid, None)
            self._can_inject.pop(pid, None)
        if handle:
            roblox.kernel32.CloseHandle(ctypes.c_void_p(handle))
            return Result(True, "link", f"detached from pid {pid}")
        return Result(False, "link", f"pid {pid} was not attached")

    def detach_all(self) -> None:
        for pid in self.attached_pids():
            self.detach(pid)

    # -- injection -------------------------------------------------------- #
    def can_inject(self, pid: int) -> bool:
        with self._lock:
            return bool(self._can_inject.get(pid))

    def inject(self, pid: int, dll_path: str, wipe: bool = True) -> Result:
        started = time.time()
        path = Path(dll_path).expanduser()
        if not path.is_file():
            return Result(False, "dll", "module not found", f"no such file: {path}")
        if path.suffix.lower() not in (".dll", ""):
            return Result(False, "dll", "not a module", "expected a .dll payload")

        if not self.is_attached(pid):
            attached = self.attach(pid)
            if not attached.ok:
                return attached

        with self._lock:
            handle = self._attached[pid]

        target = str(path.resolve())
        payload = ctypes.create_unicode_buffer(target)
        size = ctypes.sizeof(payload)
        kernel32 = roblox.kernel32

        remote = kernel32.VirtualAllocEx(
            ctypes.c_void_p(handle),
            None,
            size,
            roblox.MEM_COMMIT | roblox.MEM_RESERVE,
            roblox.PAGE_READWRITE,
        )
        if not remote:
            return Result(
                False,
                "dll",
                "VirtualAllocEx failed",
                f"WinError {ctypes.get_last_error()} -- the target has probably "
                "blocked remote allocation (anti-tamper), or you are not elevated.",
            )

        written = ctypes.c_size_t(0)
        ok = kernel32.WriteProcessMemory(
            ctypes.c_void_p(handle),
            ctypes.c_void_p(remote),
            ctypes.cast(payload, ctypes.c_void_p),
            size,
            ctypes.byref(written),
        )
        if not ok:
            kernel32.VirtualFreeEx(ctypes.c_void_p(handle), ctypes.c_void_p(remote), 0, roblox.MEM_RELEASE)
            return Result(False, "dll", "WriteProcessMemory failed", f"WinError {ctypes.get_last_error()}")

        thread = kernel32.CreateRemoteThread(
            ctypes.c_void_p(handle),
            None,
            0,
            ctypes.c_void_p(self._resolve_load_library()),
            ctypes.c_void_p(remote),
            0,
            None,
        )
        if not thread:
            error = ctypes.get_last_error()
            kernel32.VirtualFreeEx(ctypes.c_void_p(handle), ctypes.c_void_p(remote), 0, roblox.MEM_RELEASE)
            return Result(
                False,
                "dll",
                "CreateRemoteThread failed",
                f"WinError {error} -- remote thread creation is the step "
                "anti-tamper blocks first.",
            )

        kernel32.WaitForSingleObject(ctypes.c_void_p(thread), 15000)
        exit_code = ctypes.c_ulong(0)
        kernel32.GetExitCodeThread(ctypes.c_void_p(thread), ctypes.byref(exit_code))
        kernel32.CloseHandle(ctypes.c_void_p(thread))

        if wipe:
            zeros = ctypes.create_string_buffer(size)
            kernel32.WriteProcessMemory(
                ctypes.c_void_p(handle),
                ctypes.c_void_p(remote),
                ctypes.cast(zeros, ctypes.c_void_p),
                size,
                ctypes.byref(written),
            )
        kernel32.VirtualFreeEx(ctypes.c_void_p(handle), ctypes.c_void_p(remote), 0, roblox.MEM_RELEASE)

        duration = int((time.time() - started) * 1000)
        module_base = int(exit_code.value or 0)
        if not module_base:
            return Result(
                False,
                "dll",
                "module failed to load",
                "The loader returned NULL. Either the module could not resolve its "
                "own imports, or the target refused it.",
                duration,
            )
        return Result(
            True,
            "dll",
            "injected",
            f"module base 0x{module_base:X}",
            duration,
        )


# --------------------------------------------------------------------------- #
# External executor bridge
# --------------------------------------------------------------------------- #
class ExternalBridge:
    """Forwards scripts to an already-installed executor's local bridge."""

    def __init__(self, url: str = "", pipe: str = "") -> None:
        self.url = url
        self.pipe = pipe

    def _candidate_urls(self) -> list[str]:
        if self.url and "PORT" not in self.url:
            return [self.url]
        out: list[str] = []
        for port in COMMON_PORTS:
            for path in PROBE_PATHS:
                out.append(f"http://127.0.0.1:{port}{path}")
        return out

    @staticmethod
    def _listening(port: int, timeout: float = 0.25) -> bool:
        """Cheap TCP check first, so probing 11 closed ports costs ~0."""
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex(("127.0.0.1", port)) == 0

    def probe(self, force_scan: bool = False) -> Result:
        """Locate an engine to relay into.

        Uses discovery rather than a fixed port list, so an engine on any port is
        found. Reports honestly when there is nothing to relay to -- a false
        positive here would make the app claim a capability it does not have.
        """
        from . import discovery  # noqa: PLC0415 - avoids an import cycle

        if self.pipe and not force_scan:
            return Result(True, "external", f"pipe configured: {self.pipe}", self.pipe)

        # Delivery must never target a stale scan, so this bypasses the cache.
        report = discovery.discover(refresh=True)
        found = report.get("candidates") or []
        http = [c for c in found if c["kind"] == "http"]
        pipes = [c for c in found if c["kind"] == "pipe"]
        folders = [c for c in found if c["kind"] == "folder"]

        if http:
            self.url = http[0]["url"]
            return Result(
                True,
                "external",
                f"engine found at {self.url}",
                f"{http[0]['evidence']} (process: {http[0]['process'] or 'unknown'})",
                extra={"scan": report},
            )
        if pipes and not self.pipe:
            self.pipe = pipes[0]["pipe"]
            return Result(
                True,
                "external",
                f"engine pipe found: {self.pipe}",
                pipes[0]["evidence"],
                extra={"scan": report},
            )
        if folders:
            return Result(
                False,
                "external",
                "found a watch folder, but no live engine",
                f"{folders[0]['folder']} belongs to {folders[0]['process']}. "
                "Set it as the auto-run folder in Settings to drop scripts into it.",
                extra={"scan": report},
            )
        return Result(
            False,
            "external",
            "no execution engine found",
            (
                f"scanned {report['scanned']} local listener(s) and the pipe namespace; "
                "nothing accepted a script. NightRelay relays scripts, it does not "
                "contain a Luau engine -- install or start one, then rescan."
            ),
            extra={"scan": report},
        )

    def scan(self, refresh: bool = False) -> dict:
        from . import discovery  # noqa: PLC0415

        return discovery.discover(refresh=refresh)

    def execute(self, code: str, pid: int | None = None) -> Result:
        import requests

        started = time.time()
        if self.pipe:
            return self._execute_pipe(code, started)

        url = self.url
        if not url or "PORT" in url:
            found = self.probe()
            if not found.ok:
                # Nothing real is listening. Prove the relay path against the
                # stub if it is up, then fall back to a watch folder.
                stub = self._relay_to_selftest(code, pid, started)
                if stub:
                    return stub
                written = self._write_autoexec(code)
                if written:
                    return written
                return found
            url = self.url

        payload = {"script": code}
        if pid:
            payload["pid"] = pid
        last = ""
        for template in (payload, {"code": code}, {"script": code, "args": []}):
            if pid and template is payload:
                template = {**template, "pid": pid}
            try:
                resp = requests.post(url, json=template, timeout=30)
                last = f"HTTP {resp.status_code}"
                if resp.status_code < 400:
                    return Result(
                        True,
                        "external",
                        "script forwarded",
                        f"{url} -> HTTP {resp.status_code}",
                        int((time.time() - started) * 1000),
                    )
            except requests.RequestException as exc:
                last = str(exc)
        written = self._write_autoexec(code)
        if written:
            return written
        return Result(False, "external", "executor rejected the script", last)

    def _relay_to_selftest(self, code: str, pid: int | None, started: float) -> Result | None:
        """Deliver to the inert stub, saying plainly that nothing executed."""
        from . import selftest_engine  # noqa: PLC0415

        eng = selftest_engine.engine()
        if not eng.running:
            return None
        import requests  # noqa: PLC0415

        url = f"http://127.0.0.1:{eng.port}/execute"
        try:
            resp = requests.post(url, json={"script": code, "pid": pid or 0}, timeout=10)
        except requests.RequestException as exc:
            return Result(False, "selftest", "self-test relay failed", str(exc))
        return Result(
            resp.status_code == 200,
            "selftest",
            "reached the self-test stub — nothing was executed",
            (
                f"{url} -> HTTP {resp.status_code}. The relay path works end to end; "
                "there is still no engine on this PC to actually run the script."
            ),
            int((time.time() - started) * 1000),
        )

    def _write_autoexec(self, code: str) -> Result | None:
        """Hand the script to an engine that watches a folder instead of a port."""
        folder = str(config.settings().get("executor.autoexec_dir", "") or "")
        if not folder:
            return None
        target = Path(folder)
        if not target.is_dir():
            return None
        try:
            path = target / "nightrelay.lua"
            path.write_text(code, "utf-8")
        except OSError as exc:
            return Result(False, "folder", "could not write to the watch folder", str(exc))
        return Result(
            True,
            "folder",
            "script written to the watch folder",
            f"{path} — the engine runs it on its own schedule",
        )

    def _execute_pipe(self, code: str, started: float) -> Result:
        try:
            with open(self.pipe, "r+b", buffering=0) as pipe:
                pipe.write(code.encode("utf-8", "replace"))
            return Result(
                True,
                "external",
                "script written to pipe",
                self.pipe,
                int((time.time() - started) * 1000),
            )
        except OSError as exc:
            return Result(False, "external", "pipe write failed", str(exc))


# --------------------------------------------------------------------------- #
# Loader bridge -- the path that actually runs code
# --------------------------------------------------------------------------- #
class LoaderEngine:
    """Runs scripts through the Lua loader sitting in the user's executor.

    This is the real path: the loader lives inside the Roblox client, asks the
    bridge for work, runs it and returns the output. Nothing is injected; the
    user's own executor is what executes.
    """

    def probe(self, force_scan: bool = False) -> Result:
        from . import bridge as bridge_mod  # noqa: PLC0415 - avoids an import cycle

        b = bridge_mod.bridge()
        if not b.running:
            return Result(False, "loader", "loader bridge is offline", "restart NightRelay")
        live = b.sessions()
        if live:
            first = live[0]
            who = first.get("player") or "a client"
            return Result(
                True,
                "loader",
                f"loader connected ({len(live)})",
                f"{who} · place {first.get('place') or first.get('game') or 'unknown'}",
                extra={"sessions": live},
            )
        return Result(
            False,
            "loader",
            "no loader connected",
            "paste the NightRelay loader into your executor's autoexec, then run it",
        )

    def scan(self) -> dict:
        from . import bridge as bridge_mod  # noqa: PLC0415

        return bridge_mod.bridge().status()

    def execute(self, code: str, pid: int | None = None) -> Result:
        from . import bridge as bridge_mod  # noqa: PLC0415

        b = bridge_mod.bridge()
        if not b.running:
            return Result(False, "loader", "loader bridge is offline", "restart NightRelay")
        started = time.time()
        try:
            wait = float(config.settings().get("executor.loader_timeout", 20))
        except (TypeError, ValueError):
            wait = 20.0
        out = b.submit(code, wait=wait)
        took = int((time.time() - started) * 1000)
        output = str(out.get("output") or "")
        if out.get("executed"):
            ok = bool(out.get("ok"))
            message = "ran in the client" if ok else "script raised an error"
            detail = out.get("error") or (output.strip().splitlines()[-1][:200] if output.strip() else "")
            return Result(ok, "loader", message, detail, out.get("duration_ms") or took,
                          extra={"output": output[:4000], "job_id": out.get("job_id", "")})
        message = out.get("error") or "no loader picked the script up"
        detail = (
            "paste the NightRelay loader into your executor's autoexec, then run it"
            if "no loader connected" in message
            else ""
        )
        return Result(False, "loader", message, detail, took)


# --------------------------------------------------------------------------- #
# Facade
# --------------------------------------------------------------------------- #
@dataclass
class Executor:
    injector: Injector = field(default_factory=Injector)
    bridge: ExternalBridge = field(default_factory=ExternalBridge)
    loader: LoaderEngine = field(default_factory=LoaderEngine)
    history: list[dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        s = config.settings()
        self.bridge = ExternalBridge(
            url=s.get("executor.external_url", ""), pipe=s.get("executor.pipe_name", "")
        )
        self.history = _load_history()

    def resolve_pid(self, pid: int | None = None) -> int | None:
        if pid:
            return pid
        if self.injector.attached_pids():
            return self.injector.attached_pids()[-1]
        client = roblox.find_client()
        return client.pid if client else None

    def attach(self, pid: int | None = None, backend: str = "auto", probe_bridge: bool = True) -> Result:
        """Link to the client, name the account, and report the delivery path."""
        target = self.resolve_pid(pid)
        if not target:
            return Result(
                False,
                "link",
                "no Roblox client is running",
                "open Roblox, then hit attach again",
            )
        link = self.injector.link(target)
        if not link.ok:
            return link

        loader = self.loader.probe() if probe_bridge else None
        bridge = None if (loader and loader.ok) else (self.bridge.probe() if probe_bridge else None)
        extra = dict(link.extra)
        extra["loader"] = {
            "ok": bool(loader and loader.ok),
            "connected": len((loader.extra or {}).get("sessions", [])) if loader else 0,
            "message": loader.message if loader else "not probed",
        }
        extra["bridge"] = {
            "ok": bool(bridge and bridge.ok),
            "url": self.bridge.url if bridge and bridge.ok else "",
            "message": bridge.message if bridge else "not probed",
        }
        parts = [link.detail]
        if loader and loader.ok:
            parts.append(f"loader connected — {loader.detail}")
        elif bridge and bridge.ok:
            parts.append(f"executor bridge live at {self.bridge.url}")
        else:
            parts.append("no engine listening — paste the NightRelay loader into your executor")
        return Result(
            True,
            "link",
            link.message,
            "; ".join(p for p in parts if p),
            extra=extra,
        )

    def execute(
        self,
        code: str,
        pid: int | None = None,
        backend: str | None = None,
        dll_path: str | None = None,
    ) -> dict:
        s = config.settings()
        backend = backend or s.get("executor.backend", "auto")
        dll_path = dll_path or s.get("executor.dll_path", "")
        target = self.resolve_pid(pid)

        started = time.time()
        if backend == "dll" or (backend == "auto" and dll_path):
            if not target:
                result = Result(False, "dll", "no Roblox client found")
            else:
                result = self.injector.inject(target, dll_path, wipe=bool(s.get("executor.wipe_buffer", True)))
            # A module on its own does not run Lua; hand the script to whichever
            # engine channel has a live loader on the other end.
            if result.ok:
                forwarded = self.loader.execute(code, target)
                if not forwarded.ok:
                    forwarded = self.bridge.execute(code, target)
                if forwarded.ok:
                    result.detail = f"{result.detail}; {forwarded.detail}".strip("; ")
        elif backend == "loader":
            result = self.loader.execute(code, target)
        elif backend == "external":
            result = self.bridge.execute(code, target)
        elif self.loader.probe().ok:
            # auto: a connected loader is the real engine, prefer it
            result = self.loader.execute(code, target)
        else:
            result = self.bridge.execute(code, target)

        entry = {
            "time": config.uptime_stamp(),
            "pid": target,
            "backend": result.backend,
            "ok": result.ok,
            "message": result.message,
            "detail": result.detail,
            "duration_ms": result.duration_ms or int((time.time() - started) * 1000),
            "bytes": len(code.encode("utf-8")),
            "preview": code.strip().splitlines()[0][:120] if code.strip() else "",
        }
        # What the script printed inside the client travels back through the
        # loader; keep it on the history entry so the UI can show it.
        if result.extra.get("output"):
            entry["output"] = result.extra["output"]
        if result.extra.get("job_id"):
            entry["job_id"] = result.extra["job_id"]
        self.record(entry)
        return entry

    def record(self, entry: dict) -> None:
        with self._lock:
            self.history.insert(0, entry)
            del self.history[60:]
            _save_history(self.history)

    def clear_history(self) -> None:
        with self._lock:
            self.history = []
            _save_history(self.history)

    def status(self) -> dict:
        s = config.settings()
        attached = self.injector.attached_pids()
        from . import bridge as bridge_mod  # noqa: PLC0415

        bridge_status = bridge_mod.bridge().status()
        return {
            "backends": ["auto", "loader", "external", "dll"],
            "backend": s.get("executor.backend", "auto"),
            "dll_path": s.get("executor.dll_path", ""),
            "attached": attached,
            "can_inject": {str(pid): self.injector.can_inject(pid) for pid in attached},
            "identity": roblox.identity(),
            "bridge_url": self.bridge.url,
            "bridge_pipe": self.bridge.pipe,
            "autoexec_dir": s.get("executor.autoexec_dir", ""),
            "loader": bridge_status,
            "history": self.history[:25],
            "elevated": roblox.is_elevated(),
        }


def _load_history() -> list[dict]:
    path = config.history_path()
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text("utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_history(history: list[dict]) -> None:
    try:
        config.history_path().write_text(json.dumps(history, indent=2), "utf-8")
    except OSError:
        pass


_executor: Executor | None = None
_lock = threading.Lock()


def executor() -> Executor:
    global _executor
    if _executor is None:
        with _lock:
            if _executor is None:
                _executor = Executor()
    return _executor
