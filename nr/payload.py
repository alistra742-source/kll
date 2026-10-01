"""Drive the executor payload DLL over its named pipe.

The flow for running a script, end to end:

    compile source -> luau bytecode          (nr/extc.py, luau-compile)
    load the payload into the client         (nr/inject.py, or nr/byovd.py)
    send the bytecode over the pipe          (here)
    the payload runs it on its own coroutine (nr_executor.c)

The pipe is per-process: ``\\.\pipe\nr_<pid>``, so several clients can be driven
at once (which is what multi-instance is for).

Framing is fixed and must match ``nr_executor.c``: a request is
``[u32 len][bytes]`` and a reply is ``[i16 ok][u32 len][bytes]``. A zero-length
request tells the payload to shut down. Bounded on both ends -- a corrupted
length ends the connection rather than hanging.
"""

from __future__ import annotations

import ctypes
import struct
import time
from dataclasses import dataclass

from . import config, humanize, inject

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateFileW.restype = ctypes.c_void_p
kernel32.CreateFileW.argtypes = [
    ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
    ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
]
kernel32.ReadFile.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p,
]
kernel32.WriteFile.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p,
]

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3

_PIPE_READ_TIMEOUT_MS = 6000


@dataclass
class PayloadResult:
    ok: bool
    message: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {"ok": self.ok, "backend": "payload", "message": self.message, "detail": self.detail}


def pipe_name(pid: int) -> str:
    return f"\\\\.\\pipe\\nr_{pid}"


class PayloadBridge:
    """One connection to the payload inside one client."""

    def __init__(self, pid: int = 0) -> None:
        self.pid = pid
        self._handle = INVALID_HANDLE_VALUE

    def connect(self, pid: int, timeout_s: float = 6.0) -> bool:
        self.close()
        self.pid = pid
        name = pipe_name(pid)
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            handle = kernel32.CreateFileW(
                name, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None
            )
            if handle and handle != INVALID_HANDLE_VALUE:
                self._handle = handle
                return True
            time.sleep(0.25)
        return False

    def close(self) -> None:
        if self._handle and self._handle != INVALID_HANDLE_VALUE:
            kernel32.CloseHandle(ctypes.c_void_p(self._handle))
        self._handle = INVALID_HANDLE_VALUE

    def _write_all(self, data: bytes) -> bool:
        buf = ctypes.create_string_buffer(data, len(data))
        written = ctypes.c_uint32(0)
        offset = 0
        while offset < len(data):
            ok = kernel32.WriteFile(
                ctypes.c_void_p(self._handle),
                ctypes.byref(buf, offset),
                len(data) - offset,
                ctypes.byref(written),
                None,
            )
            if not ok or written.value == 0:
                return False
            offset += written.value
        return True

    def _read_exact(self, size: int) -> bytes | None:
        out = ctypes.create_string_buffer(size)
        got = ctypes.c_uint32(0)
        offset = 0
        while offset < size:
            ok = kernel32.ReadFile(
                ctypes.c_void_p(self._handle),
                ctypes.byref(out, offset),
                size - offset,
                ctypes.byref(got),
                None,
            )
            if not ok or got.value == 0:
                return None
            offset += got.value
        return out.raw[:size]

    def execute_bytecode(self, bytecode: bytes) -> PayloadResult:
        if self._handle == INVALID_HANDLE_VALUE:
            return PayloadResult(False, "not connected to the payload")
        if not bytecode:
            return PayloadResult(False, "no bytecode")

        header = struct.pack("<I", len(bytecode))
        if not self._write_all(header + bytecode):
            return PayloadResult(False, "the pipe refused the script", "write failed")

        raw = self._read_exact(2 + 4)
        if raw is None:
            return PayloadResult(False, "no reply from the payload", "read failed")
        ok, length = struct.unpack("<hI", raw)
        length = min(length, 4096)
        detail = ""
        if length:
            body = self._read_exact(length)
            detail = body.decode("utf-8", "replace") if body else ""
        return PayloadResult(bool(ok), "ran in the client" if ok else "script failed", detail)


_bridge: PayloadBridge | None = None


def bridge() -> PayloadBridge:
    global _bridge
    if _bridge is None:
        _bridge = PayloadBridge()
    return _bridge


def run(pid: int, code: str, dll_path: str = "") -> PayloadResult:
    """Compile, ensure the payload is loaded, and run the script.

    Loading is lazy: if the pipe is not already up, the DLL is loaded first (via
    the kernel driver, or BYOVD when configured), with a human-scale settle
    pause so the load does not land in the client's startup spike.
    """
    from . import extc  # noqa: PLC0415 - avoids an import cycle

    compiled = extc.compile_script(code)
    if compiled is None:
        return PayloadResult(
            False,
            "no Luau compiler available",
            "put luau-compile in tools/ or set LUAU_COMPILE",
        )

    page = bridge()
    if not page.connect(pid, timeout_s=1.0):
        dll = dll_path or str(config.settings().get("executor.payload_dll", "") or "")
        if not dll:
            return PayloadResult(False, "executor payload is not loaded", "no payload DLL configured")

        if humanize.ok():
            humanize.settle("before loading the payload")

        loaded = inject.load_module(pid, dll)
        if not loaded.ok:
            # Fall back to the BYOVD path when configured and the plain load
            # was refused -- that is the whole point of having it.
            from . import byovd  # noqa: PLC0415

            mapped = byovd.load(dll)
            if not mapped.get("ok"):
                return PayloadResult(False, "could not load the executor payload", loaded.detail)

        if not page.connect(pid, timeout_s=8.0):
            return PayloadResult(False, "payload loaded but the pipe never opened")

    result = page.execute_bytecode(compiled)
    if humanize.ok():
        humanize.breathe()
    return result
