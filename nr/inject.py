"""Load a module into the client without usermode injection.

``CreateRemoteThread`` is refused by the client -- ``inject_bench.py`` measured it
returning ``0xC000071C``. This does not use it. The path is:

    1. resolve ``LoadLibraryW`` inside the target (walk its own kernel32 export
       table through the driver, so we get the address *in the client*, not ours),
    2. allocate a buffer in the target from the kernel (``nr/km.alloc``),
    3. write the wide DLL path into it (``nr/km.write``),
    4. call ``LoadLibraryW`` from kernel context (``nr/km.call``).

No process handle is opened at any point, and no remote thread is created --
both are things a usermode anti-tamper hook would otherwise see. The only actor
that touches the client is the kernel driver.

The DLL this loads is the executor core (``payload/``): once it is inside, it
owns the Luau state and the app talks to it over a local channel.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from . import km

PAGE_READWRITE = 0x04

# PE/COFF constants we need.
_IMAGE_DOS_SIGNATURE = 0x5A4D
_IMAGE_NT_SIGNATURE = 0x00004550
_EXPORT_DIR_OFFSET_PE32P = 0x70   # DataDirectory[0] in a PE32+ optional header
_SECTION_ALIGNMENT = 0x1000


@dataclass
class LoadResult:
    ok: bool
    message: str
    detail: str = ""
    base: int = 0
    stage: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "backend": "external_core",
            "message": self.message,
            "detail": self.detail,
            "stage": self.stage,
            "base": hex(self.base) if self.base else "",
        }


# --------------------------------------------------------------------------- #
# PE reading, through the driver (reads happen in the target's memory)
# --------------------------------------------------------------------------- #
def _u16(drv: km.KernelDriver, address: int) -> int:
    data = drv.read(address, 2)
    return struct.unpack("<H", data)[0] if data else 0


def _u32(drv: km.KernelDriver, address: int) -> int:
    data = drv.read(address, 4)
    return struct.unpack("<I", data)[0] if data else 0


def find_export(drv: km.KernelDriver, module: str, name: str) -> tuple[int, str]:
    """Address of an exported function inside the target, or (0, reason).

    Uses the target's own module base from the driver, so the returned address is
    valid *in the client*, which is what ``call`` needs.
    """
    got = drv.get_base(module)
    if not got:
        return 0, f"{module} not found in the target"
    base, _size = got

    if _u16(drv, base) != _IMAGE_DOS_SIGNATURE:
        return 0, "target module has no MZ header"
    nt = base + _u32(drv, base + 0x3C)
    if _u32(drv, nt) != _IMAGE_NT_SIGNATURE:
        return 0, "target module has no PE signature"

    opt = nt + 0x18
    export_rva = _u32(drv, opt + _EXPORT_DIR_OFFSET_PE32P)
    if not export_rva:
        return 0, "target module exports nothing"

    directory = base + export_rva
    count = _u32(drv, directory + 0x18)
    addr_funcs = base + _u32(drv, directory + 0x1C)
    addr_names = base + _u32(drv, directory + 0x20)
    addr_ords = base + _u32(drv, directory + 0x24)

    if count > 4096:
        return 0, "implausible export count"   # trust nothing blind

    for i in range(count):
        name_rva = _u32(drv, addr_names + i * 4)
        if not name_rva:
            continue
        raw = drv.read(base + name_rva, len(name) + 1)
        if not raw:
            continue
        if raw[: len(name)] == name.encode("ascii") and raw[len(name)] == 0:
            ordinal = _u16(drv, addr_ords + i * 2)
            func_rva = _u32(drv, addr_funcs + ordinal * 4)
            if func_rva:
                return base + func_rva, "ok"
    return 0, f"{name} not exported by {module}"


# --------------------------------------------------------------------------- #
# Loader
# --------------------------------------------------------------------------- #
def load_module(pid: int, dll_path: str) -> LoadResult:
    """Load ``dll_path`` into ``pid`` via the kernel execution primitive."""
    path = Path(dll_path).expanduser()
    if not path.is_file():
        return LoadResult(False, "module not found", f"no such file: {path}", stage="check")

    drv = km.driver()
    if not drv.open():
        return LoadResult(
            False,
            "kernel driver not loaded",
            "build and load driver/nightrelay.sys in a VM (see driver/README.md)",
            stage="open",
        )

    if drv.attached_pid != pid:
        if not drv.attach(pid):
            return LoadResult(False, "driver refused attach", f"pid {pid}", stage="attach")

    load_library, reason = find_export(drv, "kernel32.dll", "LoadLibraryW")
    if not load_library:
        return LoadResult(False, "could not resolve LoadLibraryW", reason, stage="resolve")

    target = str(path.resolve())
    wide = target.encode("utf-16-le") + b"\x00\x00"

    buffer = drv.alloc(len(wide))
    if not buffer:
        return LoadResult(
            False,
            "kernel allocation in the target failed",
            "ZwAllocateVirtualMemory returned nothing -- target may be terminating",
            stage="alloc",
        )
    if not drv.write(buffer, wide):
        return LoadResult(False, "could not write the module path", stage="write")

    returned = drv.call(load_library, (buffer,))
    if returned is None:
        return LoadResult(
            False,
            "the call did not complete",
            "driver reported a fault invoking LoadLibraryW",
            stage="call",
        )
    if not returned:
        # LoadLibraryW returns NULL when it refuses. This is the client telling
        # us the load was denied, and it is reported as such, never as success.
        return LoadResult(
            False,
            "the client refused the module",
            "LoadLibraryW returned NULL inside the target",
            stage="call",
        )

    return LoadResult(
        True,
        "module loaded through the kernel",
        f"{path.name} -> base 0x{returned:X}",
        base=returned,
        stage="load",
    )


def ready(pid: int) -> dict:
    """Pre-flight: is every piece in place to load a module?"""
    drv = km.driver()
    status = drv.status()
    out = {"driver": status, "pid": pid}
    if status.get("loaded") and pid:
        if drv.attached_pid != pid and not drv.attach(pid):
            out["attached"] = False
            out["message"] = "attach failed"
            return out
        address, reason = find_export(drv, "kernel32.dll", "LoadLibraryW")
        out["attached"] = bool(drv.attached_pid)
        out["load_library"] = hex(address) if address else ""
        out["resolution"] = reason
        out["ready"] = bool(address)
    else:
        out["ready"] = False
        out["message"] = "driver not loaded or no pid"
    return out
