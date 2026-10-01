"""Talk to the NightRelay kernel driver.

The app is Python; the driver is a WDM device. This is the bridge between them.

Why a driver at all: ``nr/manualmap.py`` and ``payload/`` measured the boundary
precisely. The client grants ``VM_READ``, ``VM_WRITE``, ``VM_OPERATION`` and
``CREATE_THREAD``, the image is written, and then nothing executes -- the remote
thread returns ``0xC000071C``. Reading and writing are wide open; *executing in
the client's context* is refused. A kernel driver is the only thing that crosses
that line, which is why every surviving executor ships one.

The driver creates no symbolic link (a link is a walkable name any anti-tamper
enumerator can find), so this opens the device object path directly through
``NtOpenFile``. ``DeviceIoControl`` works on the resulting handle.

IOCTL codes and the request layouts must stay byte-for-byte identical to
``driver/nightrelay.h``; a mismatch is a silently wrong answer, not an error.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import struct
from dataclasses import dataclass

# --- device ---------------------------------------------------------------- #
DEVICE_PATH = "\\Device\\NightRelay"

FILE_DEVICE_UNKNOWN = 0x22
METHOD_BUFFERED = 0x0
FILE_ANY_ACCESS = 0x0


def _ctl_code(function: int) -> int:
    # CTL_CODE(DeviceType, Function, Method, Access) -- same macro the header uses.
    return (
        (FILE_DEVICE_UNKNOWN << 16)
        | (FILE_ANY_ACCESS << 14)
        | (function << 2)
        | METHOD_BUFFERED
    )


IOCTL_ATTACH = _ctl_code(0x801)
IOCTL_READ = _ctl_code(0x802)
IOCTL_WRITE = _ctl_code(0x803)
IOCTL_GET_BASE = _ctl_code(0x804)
IOCTL_STRIP_HANDLE = _ctl_code(0x805)
IOCTL_ELEVATE = _ctl_code(0x806)
IOCTL_QUERY = _ctl_code(0x807)

# --- nt load surface ------------------------------------------------------- #
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

OBJ_CASE_INSENSITIVE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
STATUS_SUCCESS = 0x00000000

ntdll.NtOpenFile.restype = ctypes.c_long
ntdll.NtOpenFile.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
]

kernel32.DeviceIoControl.restype = wintypes.BOOL
kernel32.DeviceIoControl.argtypes = [
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


class _OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", ctypes.c_void_p),
        ("ObjectName", ctypes.POINTER(_UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


# --- request layouts (mirror nightrelay.h) --------------------------------- #
class NR_PID_REQ(ctypes.Structure):
    _pack_ = 8
    _fields_ = [("Pid", wintypes.ULONG)]


class NR_RW_REQ(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("Address", ctypes.c_ulonglong),
        ("Size", wintypes.ULONG),
        ("Pad", wintypes.ULONG),
    ]


class NR_BASE_REQ(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("Module", wintypes.WCHAR * 64),
        ("Base", ctypes.c_ulonglong),
        ("Size", wintypes.ULONG),
        ("Pad", wintypes.ULONG),
    ]


class NR_QUERY_RES(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("Attached", wintypes.ULONG),
        ("Pid", wintypes.ULONG),
        ("TargetProcess", ctypes.c_ulonglong),
    ]


@dataclass
class QueryResult:
    attached: bool
    pid: int
    target_process: int

    def to_dict(self) -> dict:
        return {
            "attached": self.attached,
            "pid": self.pid,
            "target_process": hex(self.target_process) if self.target_process else "",
        }


class KernelDriver:
    """Handle to the NightRelay device.

    Every method returns a plain value or ``None``/``False`` on refusal -- the
    driver fails closed, so a failed read leaves no stale data and a failed
    attach leaves the previous target alone. Nothing here raises for a normal
    refusal; only a missing driver or a malformed request is exceptional, and
    those surface as ``False`` from :meth:`open`.
    """

    def __init__(self) -> None:
        self._handle: int | None = None
        self._attached_pid: int = 0

    # -- lifecycle --------------------------------------------------------- #
    def open(self) -> bool:
        if self._handle:
            return True
        name = _UNICODE_STRING()
        buf = ctypes.create_unicode_buffer(DEVICE_PATH)
        name.Buffer = ctypes.cast(buf, ctypes.c_void_p)
        name.Length = len(DEVICE_PATH) * ctypes.sizeof(ctypes.c_wchar)
        name.MaximumLength = name.Length + ctypes.sizeof(ctypes.c_wchar)

        attrs = _OBJECT_ATTRIBUTES()
        attrs.Length = ctypes.sizeof(_OBJECT_ATTRIBUTES)
        attrs.ObjectName = ctypes.pointer(name)
        attrs.Attributes = OBJ_CASE_INSENSITIVE

        handle = ctypes.c_void_p()
        iosb = (ctypes.c_ubyte * 16)()
        status = ntdll.NtOpenFile(
            ctypes.byref(handle),
            wintypes.DWORD(0xC0000000),  # GENERIC_READ | GENERIC_WRITE
            ctypes.byref(attrs),
            ctypes.byref(iosb),
            wintypes.ULONG(0x3),  # FILE_SHARE_READ | FILE_SHARE_WRITE
            wintypes.ULONG(FILE_SYNCHRONOUS_IO_NONALERT),
        )
        if status != STATUS_SUCCESS or not handle.value:
            return False
        self._handle = handle.value
        return True

    def close(self) -> None:
        if self._handle:
            kernel32.CloseHandle(ctypes.c_void_p(self._handle))
            self._handle = None
            self._attached_pid = 0

    def available(self) -> bool:
        """True when the driver is loaded and reachable."""
        was_open = bool(self._handle)
        if not self.open():
            return False
        try:
            return self.query() is not None
        finally:
            if not was_open:
                # Leave the handle open: the caller asked about availability and
                # will likely use it immediately.
                pass

    # -- ioctl helper ------------------------------------------------------ #
    def _ioctl(self, code: int, in_buf, in_size: int, out_size: int = 0):
        if not self._handle:
            return None
        # METHOD_BUFFERED shares one SystemBuffer; size it to the larger side.
        total = max(in_size, out_size)
        buf = ctypes.create_string_buffer(total if total else 1)
        if in_buf is not None and in_size:
            ctypes.memmove(buf, in_buf, in_size)
        returned = wintypes.DWORD(0)
        ok = kernel32.DeviceIoControl(
            ctypes.c_void_p(self._handle),
            wintypes.DWORD(code),
            ctypes.cast(buf, ctypes.c_void_p),
            wintypes.DWORD(in_size),
            ctypes.cast(buf, ctypes.c_void_p),
            wintypes.DWORD(out_size),
            ctypes.byref(returned),
            None,
        )
        if not ok:
            return None
        return buf.raw[: returned.value] if returned.value else b""

    # -- operations -------------------------------------------------------- #
    def attach(self, pid: int) -> bool:
        req = NR_PID_REQ(Pid=pid)
        result = self._ioctl(IOCTL_ATTACH, ctypes.byref(req), ctypes.sizeof(req))
        if result is not None:
            self._attached_pid = pid
            return True
        return False

    @property
    def attached_pid(self) -> int:
        return self._attached_pid

    def read(self, address: int, size: int) -> bytes | None:
        if size <= 0:
            return b""
        req = NR_RW_REQ(Address=address, Size=size, Pad=0)
        out = self._ioctl(IOCTL_READ, ctypes.byref(req), ctypes.sizeof(req), size)
        if out is None or len(out) < size:
            return None
        return bytes(out[:size])

    def write(self, address: int, data: bytes) -> bool:
        if not data:
            return False
        req = NR_RW_REQ(Address=address, Size=len(data), Pad=0)
        blob = ctypes.create_string_buffer(ctypes.sizeof(req) + len(data))
        ctypes.memmove(blob, ctypes.byref(req), ctypes.sizeof(req))
        ctypes.memmove(ctypes.addressof(blob) + ctypes.sizeof(req), data, len(data))
        result = self._ioctl(
            IOCTL_WRITE, ctypes.addressof(blob), ctypes.sizeof(req) + len(data)
        )
        return result is not None

    def read_uint64(self, address: int) -> int | None:
        raw = self.read(address, 8)
        if raw is None:
            return None
        return struct.unpack("<Q", raw)[0]

    def read_int32(self, address: int) -> int | None:
        raw = self.read(address, 4)
        if raw is None:
            return None
        return struct.unpack("<i", raw)[0]

    def write_uint64(self, address: int, value: int) -> bool:
        return self.write(address, struct.pack("<Q", value))

    def get_base(self, module: str) -> tuple[int, int] | None:
        req = NR_BASE_REQ()
        req.Module = module
        result = self._ioctl(
            IOCTL_GET_BASE, ctypes.byref(req), ctypes.sizeof(req), ctypes.sizeof(req)
        )
        if not result:
            return None
        out = NR_BASE_REQ.from_buffer_copy(result)
        if not out.Base:
            return None
        return int(out.Base), int(out.Size)

    def elevate(self) -> bool:
        return self._ioctl(IOCTL_ELEVATE, None, 0) is not None

    def strip_handle(self) -> bool:
        return self._ioctl(IOCTL_STRIP_HANDLE, None, 0) is not None

    def query(self) -> QueryResult | None:
        result = self._ioctl(IOCTL_QUERY, None, 0, ctypes.sizeof(NR_QUERY_RES))
        if not result or len(result) < ctypes.sizeof(NR_QUERY_RES):
            return None
        out = NR_QUERY_RES.from_buffer_copy(result)
        return QueryResult(
            attached=bool(out.Attached),
            pid=int(out.Pid),
            target_process=int(out.TargetProcess),
        )

    def status(self) -> dict:
        if not self.open():
            return {"loaded": False, "message": "driver not reachable"}
        q = self.query()
        return {
            "loaded": True,
            "attached": bool(q and q.attached),
            "pid": q.pid if q else 0,
            "target_process": hex(q.target_process) if q and q.target_process else "",
        }


_driver: KernelDriver | None = None


def driver() -> KernelDriver:
    """Process-wide driver handle."""
    global _driver
    if _driver is None:
        _driver = KernelDriver()
    return _driver
