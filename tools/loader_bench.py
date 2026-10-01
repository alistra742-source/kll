"""Prove the loader bridge executes end to end.

A simulated loader stands in for the Lua one that runs inside Roblox: it
registers, polls for work, and reports a canned result. Running this after
touching nr/bridge.py or the loader backend in nr/executor.py shows whether the
pieces still fit -- the same separation tools/scan_bench.py gives the scanner.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nr import bridge, executor  # noqa: E402

PORT = 8796


def _post(path: str, obj: dict) -> dict:
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}{path}",
        data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def _get(path: str) -> dict:
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=5) as resp:
        return json.loads(resp.read())


def fake_loader(stop: threading.Event) -> None:
    reg = _post("/register", {"session": "bench", "player": "BenchTater", "place": "0"})
    sid = reg["id"]
    while not stop.is_set():
        polled = _get(f"/poll?id={sid}")
        if not polled.get("ok"):
            print("  loader: bridge forgot the session")
            return
        for job in polled.get("jobs", []):
            script = job["script"]
            # Stand in for a Lua run: an intentional error stays an error.
            if "error(" in script:
                _post("/report", {"id": sid, "job_id": job["job_id"], "ok": False,
                                  "error": "bench: deliberate failure", "duration_ms": 3})
            else:
                _post("/report", {"id": sid, "job_id": job["job_id"], "ok": True,
                                  "output": "ran: " + script.strip(), "duration_ms": 4})
        time.sleep(0.05)


def main() -> int:
    started = bridge.bridge().start(PORT)
    if not started.get("ok"):
        print(f"FAIL: bridge did not start -- {started.get('message')}")
        return 1

    ok = True
    ex = executor.executor()

    # 1. no loader yet -> a clear refusal, never a fake success
    pending = ex.execute("print('nobody home')", backend="loader")
    print(f"before loader: ok={pending['ok']} :: {pending['message']}")
    if pending["ok"]:
        print("FAIL: execution claimed success with no loader connected")
        ok = False

    stop = threading.Event()
    threading.Thread(target=fake_loader, args=(stop,), daemon=True).start()
    time.sleep(0.4)

    # 2. loader live -> the script runs and the output comes back
    good = ex.execute("print('hello from the client')", backend="loader")
    print(f"good run: ok={good['ok']} backend={good['backend']} :: {good['message']}")
    print(f"  output: {good.get('output')!r}")
    if not good["ok"] or good["backend"] != "loader":
        print("FAIL: a live loader did not run the script")
        ok = False
    if "hello from the client" not in (good.get("output") or ""):
        print("FAIL: the reported output did not survive the round trip")
        ok = False

    # 3. a failing script is executed but reported as a failure
    bad = ex.execute("error('boom')", backend="loader")
    print(f"bad run: ok={bad['ok']} :: {bad['message']} :: {bad.get('detail')}")
    if bad["ok"]:
        print("FAIL: a script that errored was reported as success")
        ok = False

    stop.set()
    time.sleep(0.3)
    bridge.bridge().stop()
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
