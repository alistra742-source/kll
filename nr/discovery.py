"""Find whatever local execution engine is available.

NightRelay is a relay. It deliberately contains no Luau engine, so execution
needs an engine to relay *to*. This module is what makes that seamless: instead
of guessing at a handful of ports, it enumerates every loopback listener with the
process that owns it, checks the named-pipe surface, and looks for the
watch-folder convention that many executors use.

Everything here is read-only discovery -- it observes what is already running and
never tries to place code anywhere.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

TCP_TABLE_OWNER_PID_LISTENER = 3
AF_INET = 2
AF_INET6 = 23

# Windows' own plumbing plus things we know are not script engines. Keeping this
# list means the scan reports engines rather than every service on the box.
NOISE_PROCESSES = {
    "system", "idle", "svchost.exe", "services.exe", "lsass.exe", "wininit.exe",
    "spoolsv.exe", "smss.exe", "csrss.exe", "winlogon.exe", "dwm.exe", "conhost.exe",
    "jhi_service.exe", "mpdefendercore.exe", "mssense.exe", "nisrv.exe",
    "msmpeng.exe", "searchindexer.exe", "wmiregistrationservice.exe",
    "epicgameslauncher.exe", "epicwebhelper.exe", "epiconlineservicesuserhelper.exe",
    "steam.exe", "steamwebhelper.exe", "voicemod.exe", "ollama.exe", "ollama app.exe",
    "nvidia share.exe", "nvdisplay.container.exe", "rtkauduservice64.exe",
    "gameinputsvc.exe", "gamingservices.exe", "gamingservicesnet.exe",
    "firefox.exe", "chrome.exe", "msedge.exe", "brave.exe", "opera.exe",
    "discord.exe", "spotify.exe", "telegram.exe", "teams.exe",
    "nightrelay.exe", "[system process]", "system idle process",
    # Only obvious consumer/system noise belongs here. Script hosts like
    # python.exe, node.exe and bun.exe are deliberately NOT excluded: an engine
    # hosted by one of those would otherwise be invisible. Detecting a real engine
    # is the strict probe's job, not this list's.
}

# Ports that are conventionally an executor bridge. Discovery no longer depends
# on these, but probing them first keeps the common case instant.
COMMON_PORTS = (6969, 5500, 5555, 3000, 4000, 8080, 7957, 25565, 3058, 13583, 3012)

PROBE_PATHS = ("/execute", "/api/execute", "/exec", "/run", "/api/run", "/", "/inject")

# Payload shapes seen across bridges that accept a script over HTTP.
PAYLOAD_SHAPES = (
    {"script": "{code}"},
    {"code": "{code}"},
    {"script": "{code}", "pid": "{pid}"},
    {"source": "{code}"},
    {"lua": "{code}"},
    {"script": "{code}", "args": []},
)

PIPE_MARKERS = (
    "executor", "solara", "wave", "xeno", "swift", "fluxus", "krnl", "synapse",
    "script", "hydrogen", "trigon", "delta", "arceus", "macsploit", "vega",
    "roblox", "rblx", "exploit", "cheat",
)

# Watch-folder conventions, newest first. An executor that auto-runs anything
# dropped here is a legitimate integration point.
AUTOEXEC_CANDIDATES = (
    ("Solara", ("Solara", "autoexec")),
    ("Wave", ("Wave", "autoexec")),
    ("Xeno", ("Xeno", "autoexec")),
    ("Swift", ("Swift", "autoexec")),
    ("Fluxus", ("Fluxus", "autoexec")),
    ("Roblox", ("Roblox", "autoexec")),
)


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


@dataclass
class Listener:
    port: int
    pid: int
    address: str = "127.0.0.1"
    process: str = ""
    path: str = ""

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "pid": self.pid,
            "address": self.address,
            "process": self.process,
            "path": self.path,
        }


@dataclass
class Candidate:
    url: str = ""
    pipe: str = ""
    folder: str = ""
    kind: str = "http"       # http | pipe | folder
    process: str = ""
    port: int = 0
    evidence: str = ""
    shape: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "pipe": self.pipe,
            "folder": self.folder,
            "kind": self.kind,
            "process": self.process,
            "port": self.port,
            "evidence": self.evidence,
            "shape": self.shape,
        }


# --------------------------------------------------------------------------- #
# Listener enumeration
# --------------------------------------------------------------------------- #
def _pid_name_map() -> dict[int, str]:
    """pid -> executable name, from the process snapshot.

    Read straight off the toolhelp snapshot rather than OpenProcess, because
    opening other users' or protected processes is usually denied and we would
    end up filtering on an empty name.
    """
    try:
        from . import roblox  # noqa: PLC0415

        return {pid: name.lower() for pid, name in roblox.list_processes()}
    except Exception:
        return {}


def _process_name(pid: int) -> str:
    """Owning executable name for a pid, without importing the roblox module."""
    try:
        from . import roblox  # noqa: PLC0415

        path = roblox.process_path(pid)
        return Path(path).name if path else ""
    except Exception:
        return ""


def list_listeners(exclude_ports: set[int] | None = None) -> list[Listener]:
    """Every TCP listener bound to loopback or all interfaces, with its owner."""
    exclude = set(exclude_ports or ())
    try:
        from . import config  # noqa: PLC0415

        exclude.add(int(config.settings().get("server.port", 8791)))
    except Exception:
        exclude.add(8791)
    # The stub and our own loader bridge are reported separately and must never
    # be mistaken for a third-party engine.
    stub_ports = _selftest_ports()
    exclude |= stub_ports
    exclude |= _bridge_ports()
    names = _pid_name_map()
    try:
        iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    except OSError:
        return []

    def table(family: int) -> list[tuple[str, int, int]]:
        size = wintypes.DWORD(0)
        iphlpapi.GetExtendedTcpTable(
            None, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_LISTENER, 0
        )
        if not size.value:
            return []
        buf = ctypes.create_string_buffer(size.value)
        ret = iphlpapi.GetExtendedTcpTable(
            buf, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_LISTENER, 0
        )
        if ret != 0:
            return []
        count = ctypes.c_uint32.from_buffer(buf).value
        if not count:
            return []
        rows = (MIB_TCPROW_OWNER_PID * count).from_buffer(buf, 4)
        out: list[tuple[str, int, int]] = []
        for row in rows:
            port = socket.ntohs(row.dwLocalPort & 0xFFFF)
            if not port:
                continue
            if family == AF_INET:
                address = socket.inet_ntoa(struct.pack("<I", row.dwLocalAddr & 0xFFFFFFFF))
            else:
                address = "::"
            out.append((address, port, int(row.dwOwningPid)))
        return out

    seen: set[tuple[int, int]] = set()
    listeners: list[Listener] = []
    # Our own listener (the UI server, the loader bridge, the stub) answers a
    # loopback POST with our own JSON, which reads exactly like an engine's ack.
    # Excluding by pid rather than by port means a --port override or an
    # ephemeral bind can never make NightRelay rediscover itself and report a
    # fake success.
    self_pid = os.getpid()
    for family in (AF_INET, AF_INET6):
        for address, port, pid in table(family):
            if address not in ("127.0.0.1", "0.0.0.0", "::", "::1"):
                continue
            if pid == self_pid:
                continue
            key = (port, pid)
            if key in seen:
                continue
            seen.add(key)
            if port in exclude:
                continue
            name = names.get(pid, "") or _process_name(pid)
            if name.lower() in NOISE_PROCESSES:
                continue
            if port in (135, 445, 5040, 2869, 7680, 49664, 49665, 49666, 49667, 49668, 49669, 49670, 27036):
                continue
            listeners.append(
                Listener(
                    port=port,
                    pid=pid,
                    address="127.0.0.1" if address in ("0.0.0.0", "::") else address,
                    process=name,
                )
            )
    listeners.sort(key=lambda item: (item.port not in COMMON_PORTS, item.port))
    return listeners


def list_pipes() -> list[str]:
    """Executor-looking named pipes."""
    found: list[str] = []
    try:
        for name in os.listdir("\\\\.\\pipe\\"):
            lowered = name.lower()
            if any(marker in lowered for marker in PIPE_MARKERS):
                found.append(f"\\\\.\\pipe\\{name}")
    except OSError:
        pass
    return sorted(set(found))


def find_autoexec_folders() -> list[tuple[str, Path]]:
    """Watch folders belonging to executors that are actually installed."""
    roots = [
        os.environ.get("LOCALAPPDATA", ""),
        os.environ.get("APPDATA", ""),
    ]
    found: list[tuple[str, Path]] = []
    for label, parts in AUTOEXEC_CANDIDATES:
        for root in roots:
            if not root:
                continue
            path = Path(root).joinpath(*parts)
            if path.is_dir():
                found.append((label, path))
    return found


# --------------------------------------------------------------------------- #
# Probing
# --------------------------------------------------------------------------- #
# Scans must stay interactive. A single silent listener can otherwise cost a
# timeout per candidate path; these budgets keep the worst case bounded.
LISTENER_BUDGET = 1.6
SCAN_BUDGET = 6.0
CACHE_TTL = 8.0

_cache: dict = {"at": 0.0, "key": None, "data": None}


def _port_open(port: int, address: str = "127.0.0.1", timeout: float = 0.2) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((address, port)) == 0


def _try_url(url: str, timeout: float = 0.9) -> tuple[bool, str, int, bool]:
    """Decide whether a URL really accepts scripts.

    Deliberately strict. A local service that merely answers -- an auth gate
    returning 401, a dev server returning its index page -- is not an engine, and
    calling it one would make the app report a capability it does not have.

    The fourth element reports a true timeout, which is the signal that a
    listener accepted the socket and then went quiet. Probing such a listener on
    every candidate path is what turns a scan into a multi-second stall.
    """
    import requests

    try:
        resp = requests.post(
            url,
            json={"script": "-- NightRelay probe"},
            timeout=timeout,
            headers={"X-NightRelay-Probe": "1"},
        )
    except requests.Timeout:
        return False, "accepted the connection but never answered", 0, True
    except requests.RequestException as exc:
        return False, type(exc).__name__, 0, False

    # Our own API answers a loopback POST with a JSON ack that reads exactly like
    # an engine. It stamps every reply so it can never be mistaken for one -- a
    # second NightRelay on the box included.
    if resp.headers.get("X-NightRelay-Self"):
        return False, "another NightRelay instance, not an engine", resp.status_code, False

    if not (200 <= resp.status_code < 300):
        return False, f"HTTP {resp.status_code} (not an accept)", resp.status_code, False

    body = resp.text[:400]
    lowered = body.lower()
    content_type = resp.headers.get("content-type", "").lower()

    # Backstop in case a copy predates the header above: our own "nothing to run"
    # envelope is not an execute response.
    if "nothing to run" in lowered or '"backend"' in lowered:
        return False, "another NightRelay instance, not an engine", resp.status_code, False

    # A 2xx is not enough on its own: a web server will happily return its own
    # index page for an unknown POST. Require something that reads like an
    # execute response.
    signals = ("error", "success", "ok", "result", "executed", "output", "script")
    looks_json = "json" in content_type or body.lstrip().startswith(("{", "["))
    if looks_json and any(token in lowered for token in signals):
        return True, f"HTTP {resp.status_code}, JSON execute response", resp.status_code, False
    if looks_json and body.strip() in ("{}", "[]"):
        return True, f"HTTP {resp.status_code}, empty JSON ack", resp.status_code, False
    return (
        False,
        f"HTTP {resp.status_code} but the body is not an execute response",
        resp.status_code,
        False,
    )


def _selftest_ports() -> set[int]:
    try:
        from . import selftest_engine  # noqa: PLC0415

        eng = selftest_engine.engine()
        return {eng.port} if eng.running else set()
    except Exception:
        return set()


def _bridge_ports() -> set[int]:
    """Ports owned by NightRelay's own loader bridge."""
    try:
        from . import bridge as bridge_mod  # noqa: PLC0415

        b = bridge_mod.bridge()
        return {b.port} if b.running else set()
    except Exception:
        return set()


def _loader_sessions() -> list[dict]:
    """Loaders currently attached to the bridge -- live execution channels."""
    try:
        from . import bridge as bridge_mod  # noqa: PLC0415

        return bridge_mod.bridge().sessions()
    except Exception:
        return []


def discover(
    include_pipes: bool = True,
    include_folders: bool = True,
    exclude_ports: set[int] | None = None,
    refresh: bool = False,
) -> dict:
    """Scan the machine for usable execution engines.

    Returns candidates ordered best-first, plus the raw listener table so the UI
    can show the user why a given port was or was not considered. Results are
    cached briefly so repeated scans are instant; pass ``refresh=True`` when the
    answer must be live (delivery, or a user-initiated rescan).
    """
    stub_ports_now = _selftest_ports()
    cache_key = (
        include_pipes,
        include_folders,
        tuple(sorted(exclude_ports or ())),
        tuple(sorted(stub_ports_now)),
        # A loader connecting or dropping must invalidate the cache immediately,
        # otherwise a fresh loader would not be seen for a few seconds.
        tuple(sorted(s["id"] for s in _loader_sessions())),
    )
    if (
        not refresh
        and _cache["data"] is not None
        and _cache["key"] == cache_key
        and (time.time() - _cache["at"] < CACHE_TTL)
    ):
        return {**_cache["data"], "cached": True}

    listeners = list_listeners(exclude_ports)
    candidates: list[Candidate] = []
    probed: list[dict] = []
    scan_deadline = time.time() + SCAN_BUDGET

    for listener in listeners:
        address = listener.address or "127.0.0.1"
        opened = _port_open(listener.port, address)
        entry = listener.to_dict()
        entry["open"] = opened
        if not opened:
            probed.append(entry)
            continue

        if time.time() > scan_deadline:
            entry["reason"] = "skipped — scan time budget reached"
            probed.append(entry)
            continue

        reason = "no path accepted a script"
        listener_deadline = time.time() + LISTENER_BUDGET
        for path in PROBE_PATHS:
            url = f"http://127.0.0.1:{listener.port}{path}"
            ok, evidence, _status, timed_out = _try_url(url)
            if ok:
                candidates.append(
                    Candidate(
                        url=url,
                        kind="http",
                        process=listener.process,
                        port=listener.port,
                        evidence=f"{evidence} on {path}",
                    )
                )
                break
            reason = evidence or reason
            if timed_out or time.time() > listener_deadline:
                # A silent listener does not deserve seven timeouts in a row.
                # The message stays actionable: a real engine answers a loopback
                # POST in milliseconds, so a hang means either it is not an
                # engine or it has a fixed endpoint worth naming in Settings.
                reason = (
                    "accepted the connection but never answered — not treated as "
                    "an engine; name its endpoint in Settings to use it anyway"
                )
                break
        entry["reason"] = reason
        probed.append(entry)

    if include_pipes:
        for pipe in list_pipes():
            candidates.append(
                Candidate(
                    pipe=pipe,
                    kind="pipe",
                    evidence="named pipe present",
                )
            )

    if include_folders:
        for label, folder in find_autoexec_folders():
            candidates.append(
                Candidate(
                    folder=str(folder),
                    kind="folder",
                    process=label,
                    evidence=f"{label} watch folder exists",
                )
            )

    # A connected loader is the strongest candidate there is: it is a live
    # channel inside a running client. Loaders sort ahead of everything else.
    loader_candidates: list[Candidate] = []
    for session in _loader_sessions():
        who = session.get("player") or "a client"
        place = session.get("place") or session.get("game") or "unknown place"
        loader_candidates.append(
            Candidate(
                url="",
                kind="loader",
                process=who,
                evidence=f"loader live in {who} · place {place}",
            )
        )
    if loader_candidates:
        candidates = loader_candidates + candidates

    # The stub is surfaced on its own line so it can never be mistaken for a
    # real engine, and so a self-test can still prove the relay path.
    stub_ports = _selftest_ports()
    for port in stub_ports:
        candidates.append(
            Candidate(
                url=f"http://127.0.0.1:{port}/execute",
                kind="selftest",
                port=port,
                process="NightRelay self-test",
                evidence="inert stub — proves the relay path, runs nothing",
            )
        )

    real = [c for c in candidates if c.kind in ("loader", "http", "pipe", "folder")]
    stubs = [c for c in candidates if c.kind == "selftest"]

    if loader_candidates:
        summary = f"{len(loader_candidates)} loader(s) connected — scripts will run"
    elif real:
        summary = f"found {len(real)} candidate engine(s)"
    elif stubs:
        summary = "no real engine; self-test stub is running"
    else:
        summary = "no execution engine found"

    report = {
        "ok": bool(real),
        "best": real[0].to_dict() if real else None,
        "candidates": [c.to_dict() for c in candidates],
        "selftest": [c.to_dict() for c in stubs],
        "listeners": probed,
        "scanned": len(listeners),
        "summary": summary,
        "cached": False,
    }
    _cache.update({"at": time.time(), "key": cache_key, "data": report})
    return report


# Public alias: callers sometimes want to test a single URL the user typed in.
try_url = _try_url


if __name__ == "__main__":  # pragma: no cover - manual diagnostic
    import json

    print(json.dumps(discover(), indent=2)[:4000])
