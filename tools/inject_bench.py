"""Prove which injection paths work, and where the client stops them.

Three paths are exercised against a process this bench owns, so a failure here
means the loader is broken:

  1. load       -- remote-thread LoadLibraryW
  2. manual     -- reflective map, entry called on a fresh remote thread
  3. apc        -- reflective map, entry reached by queueing an APC (no new thread)

With ``--client`` it then runs the same three against a live Roblox client and
reports what the client actually permits. That mode is a report, not a
pass/fail: a protected client is expected to refuse execution, and the point is
to see exactly which step it refuses rather than guess.

Requires payload/nr_beacon.dll; build it with payload\\build_payload.bat first.
"""

from __future__ import annotations

import ctypes
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nr import executor, manualmap, roblox  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DLL = ROOT / "payload" / "nr_beacon.dll"
BEACON = str(DLL) + ".beacon.txt"

# A child that parks its main thread in an alertable wait, so an APC can land.
CONTROL_CHILD = (
    "import ctypes\n"
    "k = ctypes.windll.kernel32\n"
    "for _ in range(40):\n"
    "    k.SleepEx(500, True)\n"
)


def _reset() -> None:
    if os.path.exists(BEACON):
        os.remove(BEACON)


def _wait_beacon(seconds: float = 6.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if os.path.exists(BEACON):
            time.sleep(0.4)  # let the writer finish
            return True
        time.sleep(0.2)
    return False


def _load(pid: int, dll: str) -> tuple[bool, str]:
    result = executor.executor().injector.inject(pid, dll, wipe=True)
    detail = f"{result.message} ({result.detail})"
    return _wait_beacon(), detail


def _manualmap(pid: int, dll: str, method: str) -> tuple[bool, str]:
    handle = executor.executor().injector._open(pid, executor.INJECT_RIGHTS)
    if not handle:
        raise RuntimeError("could not open the process")
    info = manualmap.map_dll(handle, pid=pid, dll_path=dll, report_path=BEACON, method=method)
    detail = f"base 0x{info['base']:X}, thread_exit 0x{info['thread_exit']:X}"
    return _wait_beacon(), detail


# A raw stub that writes a magic word. This is what APC delivery is judged on:
# whether queued code runs at all. Wiring the full image through an APC callback
# is a separate, later concern -- an APC that never fires and a DllMain that
# cannot run under one look identical if you test them together.
_MAGIC = 0x12345678


def _apc_delivery(pid: int, dll: str) -> tuple[bool, str]:
    del dll
    handle = executor.executor().injector._open(pid, executor.INJECT_RIGHTS)
    if not handle:
        raise RuntimeError("could not open the process")
    scratch = manualmap._alloc(handle, 0x1000)
    flag, stub_addr = scratch, scratch + 0x100
    stub = (
        b"\x48\xB8" + struct.pack("<Q", flag)
        + b"\x48\xC7\x00" + struct.pack("<I", _MAGIC)
        + b"\xC3"
    )
    manualmap._write(handle, stub_addr, stub)

    k = manualmap.kernel32
    rights = manualmap.THREAD_SET_CONTEXT | manualmap.THREAD_SUSPEND_RESUME | manualmap.THREAD_QUERY_INFORMATION
    queued = refused = 0
    for tid in manualmap.thread_ids(pid):
        thread = k.OpenThread(rights, False, tid)
        if not thread:
            refused += 1
            continue
        if k.QueueUserAPC(ctypes.c_void_p(stub_addr), ctypes.c_void_p(int(thread)), 0):
            queued += 1
        k.CloseHandle(ctypes.c_void_p(int(thread)))

    buf = (ctypes.c_char * 8)()
    ran = False
    for _ in range(24):
        if k.ReadProcessMemory(
            ctypes.c_void_p(handle), ctypes.c_void_p(flag), buf, 8, None
        ) and struct.unpack("<Q", buf.raw)[0] == _MAGIC:
            ran = True
            break
        time.sleep(0.25)
    return ran, f"queued to {queued} thread(s), {refused} handle(s) refused"


PATHS = (
    ("load", _load),
    ("manual", lambda pid, dll: _manualmap(pid, dll, "thread")),
    ("apc", _apc_delivery),
)


def probe(label: str, pid: int, expect: bool) -> bool:
    print(f"\n[{label}] pid {pid}")
    okay = True
    for name, run in PATHS:
        _reset()
        try:
            ran, detail = run(pid, str(DLL))
        except Exception as exc:  # noqa: BLE001 - the message is the result
            print(f"  {name:8} -> not delivered: {exc}")
            okay = False
            continue
        print(f"  {name:8} -> {'RAN' if ran else 'NO EXECUTION'}   {detail}")
        if expect and not ran:
            okay = False
        if ran and not expect:
            print(f"    note: {name} executed in a target expected to refuse it")
    return okay


def main(argv: list[str]) -> int:
    if not DLL.is_file():
        print(f"payload missing: {DLL}\nbuild it: payload\\build_payload.bat")
        return 1

    print(f"payload: {DLL} ({DLL.stat().st_size} bytes)")

    child = subprocess.Popen([sys.executable, "-c", CONTROL_CHILD])
    try:
        time.sleep(1.5)
        control_ok = probe("CONTROL", child.pid, expect=True)
    finally:
        child.terminate()

    print("\nPASS" if control_ok else "\nFAIL: a path the loader owns did not run")
    exit_code = 0 if control_ok else 1

    if "--client" in argv:
        clients = roblox.find_roblox(include_studio=False)
        if not clients:
            print("\n[client] no Roblox client is running")
        else:
            client = clients[-1]
            print(f"\nclient build: {client.version}")
            # A refusal here is the expected outcome, so it does not fail the run.
            probe("CLIENT (informational)", client.pid, expect=False)
            print(
                "\nRead the client block above literally: whatever says 'RAN' is a\n"
                "path the client permits, and whatever says 'no execution' is one it\n"
                "neutralises. Nothing is inferred from the exit codes alone."
            )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
