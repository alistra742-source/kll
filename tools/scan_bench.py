"""Prove the scan stays interactive when a listener accepts but never answers.

That listener is the only case that used to blow the scan up to several seconds:
every candidate path paid a full HTTP timeout. Run this after touching the
probing budgets in nr/discovery.py.

The silent listener runs in a *child process* on purpose. Discovery excludes the
current process's own listeners -- NightRelay must never rediscover its own UI
server as an engine -- so a listener bound in this process would be invisible by
design. A child stands in for "some other app on the box".
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nr import discovery  # noqa: E402

HANG_PORT = 8797

CHILD = """
import socket, sys, time
port = int(sys.argv[1])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen(16)
held = []
while True:
    try:
        conn, _ = server.accept()
    except OSError:
        break
    held.append(conn)  # kept open, never written to
"""


def start_silent_listener(port: int) -> subprocess.Popen:
    """Launch a child that accepts connections and then says nothing, forever."""
    proc = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 8.0
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return proc
        time.sleep(0.1)
    proc.terminate()
    raise RuntimeError(f"silent listener on {port} never came up")


def main() -> int:
    proc = start_silent_listener(HANG_PORT)
    try:
        # Warm the connection table so the listener is definitely listed.
        discovery.discover(refresh=True)

        started = time.time()
        report = discovery.discover(refresh=True)
        elapsed = time.time() - started

        silent = [l for l in report["listeners"] if "never answered" in (l.get("reason") or "")]
        print(f"scan took {elapsed * 1000:.0f}ms over {report['scanned']} listener(s)")
        print(f"silent listeners detected: {[l['port'] for l in silent]}")
        print(f"candidates (must be empty): {report['candidates']}")

        ok = True
        if elapsed > discovery.SCAN_BUDGET + 2.0:
            print(f"FAIL: scan exceeded the budget ({elapsed:.1f}s)")
            ok = False
        if HANG_PORT not in [l["port"] for l in silent]:
            print(f"FAIL: the silent listener on {HANG_PORT} was not identified")
            ok = False
        if report["candidates"]:
            print("FAIL: a silent listener was reported as an engine")
            ok = False

        cached_started = time.time()
        discovery.discover(refresh=False)
        cached_ms = (time.time() - cached_started) * 1000
        print(f"cached scan took {cached_ms:.0f}ms")
        if cached_ms > 50:
            print("FAIL: the cached path is not instant")
            ok = False

        print("PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
